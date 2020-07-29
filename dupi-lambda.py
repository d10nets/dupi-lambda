# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Author:         Dirk Tennie <dirk@d10nets.com>
# Description:    AWS lambda function to export AWS flow logs to dedicated
#                 EC2 monitoring host for flow log analysis and alerting
#
import os
import time
import socket
import json
import base64
import gzip
import struct
import array
import ipaddress
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# define dupi pdu header format and fields
dupi_pdu_hformat = '! H H I I I 16s'
dupi_pdu_hkeys = [
    'pdu_version',       # dupi pdu version
    'flow_count',        # flow count in this pdu (1-40)
    'timestamp_sec',     # epoch seconds
    'timestamp_nsecs',   # epoch nanoseconds
    'sampling',          # sampling factor 1/n
    'site_name'          # site name of flow origin
]

# define dupi pdu record format and fields
dupi_pdu_rformat = '! I I I I I I H H B B H'
dupi_pdu_rkeys = [
    'sip',               # source ip address
    'dip',               # destination ip address
    'packets',           # number of packets in the flow
    'bytes',             # number of bytes in the flow
    'start',             # start time of flow
    'end',               # end time of flow
    'sp',                # tcp/udp source port
    'dp',                # tcp/udp destination port
    'flags',             # cumulative tcp flags
    'proto',             # ip protocol type
    'pad'                # padding
]

# define aws flow log record keys
aws_flowlog_keys = [
    'version',           # aws version
    'account-id',        # aws acount id
    'interface-id',      # aws interface id
    'srcaddr',           # flow source ip address
    'dstaddr',           # flow destination ip address
    'srcport',           # flow source port
    'dstport',           # flow destination port
    'protocol',          # flow ip protocol type
    'packets',           # flow number of packets
    'bytes',             # flow number of bytes
    'start',             # flow start time in epoch seconds
    'end',               # flow end time in epoch seconds
    'action',            # aws connection accept/reject
    'log-status'         # aws connection status
]

# define mapping between dupi record keys and aws flow log keys
aws_flowlog_map = [3, 4, 8, 9, 10, 11, 5, 6, None, 7, None]


# convert flow log message to dupi pdu
def dupi_flowlog2pdu(msg):
    # get collector host and port from environment variables
    dest_host = os.environ['DESTINATION_HOST']
    dest_port = os.environ['DESTINATION_PORT']
    site_name = "aws-site"
    if 'SITE_NAME' in os.environ:
        site_name = os.environ['SITE_NAME']
    try:
        addrfamily = socket.getaddrinfo(dest_host, dest_port)[0][0]
    except Exception as e:
        wmsg = "Destination host %s:%s invalid (%s)" % (dest_host, dest_port, e)
        logger.warning(wmsg)
        return {'statusCode': 500, 'body': json.dumps(msg)}

    # get message type
    if "DATA_MESSAGE" != msg['messageType']:
        wmsg = "Received invalid message with type %s" % msg['messageType']
        logger.warning(wmsg)
        return {'statusCode': 400, 'body': json.dumps(wmsg)}

    # log flow log message
    logger.debug("FLOW LOG MESSAGE INPUT:")
    for key in msg:
        if key != "logEvents":
            logger.debug(" %-19s: %s", key, msg[key])
    num_records = len(msg['logEvents'])
    logger.debug(" %-19s: %s", "logEvents", str(num_records))

    # build dupi pdus with max flows per pdu (mtu-(ip+udp)=1500-(20+8))
    pduh = struct.Struct(dupi_pdu_hformat)
    pdur = struct.Struct(dupi_pdu_rformat)
    pdu_rmax = (1472-pduh.size)//pdur.size
    num_records_pdu = ([pdu_rmax]*(num_records//pdu_rmax) + [num_records % pdu_rmax]*((num_records % pdu_rmax) != 0))
    for pdu_index, num_flows in enumerate(num_records_pdu):
        # build dupi pdu header
        pdu = array.array('B', [0] * (pduh.size+(pdur.size*num_flows)))
        now_sec = time.time()
        now_nsec = (now_sec-int(now_sec))*(10**9)
        logger.debug("DUPI PDU #%s OUTPUT:", pdu_index+1)

        # build dupi pdu records
        for event_index, flowlog in enumerate(msg['logEvents'][pdu_rmax*pdu_index:(pdu_rmax*pdu_index)+num_flows]):
            logger.debug(" DUPI PDU Record #%s", event_index+1)
            # for key in flowlog:
            #     if key != "message":
            #         logger.debug("    %-13s: %s", key, flowlog[key])
            fvals = flowlog['message'].split()
            if len(fvals) == len(aws_flowlog_keys):
                records = []
                for key_index, key in enumerate(dupi_pdu_rkeys):
                    if aws_flowlog_map[key_index] is not None:
                        if key == 'sip' or key == 'dip':
                            records.append(int(ipaddress.IPv4Address(fvals[aws_flowlog_map[key_index]])))
                        else:
                            records.append(int(fvals[aws_flowlog_map[key_index]]))
                        logger.debug("  %-13s: %s", key, fvals[aws_flowlog_map[key_index]])
                    else:
                        records.append(0)
                        logger.debug("  %-13s: 0", key)
                pdur.pack_into(pdu, pduh.size+(pdur.size*event_index), *records)
            else:
                wmsg = "Received invalid flow log message"
                logger.warning(wmsg)
                return {'statusCode': 400, 'body': json.dumps(wmsg)}

        # build dupi pdu header with version, flow count, epoch secs, nsecs, sampling, site_name
        header = [20, num_flows, int(now_sec), int(now_nsec), 1, site_name.encode()]
        logger.debug(" DUPI PDU Header")
        for key_index, key in enumerate(dupi_pdu_hkeys):
            logger.debug("  %-17s: %s", key, header[key_index])
        pduh.pack_into(pdu, 0, *header)

        # export flow log records to collector
        try:
            sock = socket.socket(addrfamily, socket.SOCK_DGRAM)
            sock.sendto(pdu, (dest_host, int(dest_port)))
            logger.info("Exported DUPI PDU #%s with %s flow records (%s bytes) to host %s:%s", pdu_index+1,
                        num_flows, pdu.buffer_info()[1] * pdu.itemsize, dest_host, dest_port)
        except Exception as e:
            wmsg = "Failed to export DUPI PDU to host %s:%s (%s)" % (dest_host, dest_port, e)
            logger.warning(wmsg)
            return {'statusCode': 500, 'body': json.dumps(wmsg)}

    # return success
    return {'statusCode': 200, 'body': json.dumps(str(num_records) + " flow log(s) successfully processed!")}


# handle event
def lambda_handler(event, context):
    logger.debug("ENVIRONMENT VARIABLES:")
    logger.debug(" %s", os.environ)
    logger.debug("CONTEXT:")
    logger.debug(" %s", context)
    logger.debug("EVENT:")
    logger.debug(" %s", event)

    msg_encoded = event['awslogs']['data']
    msg_decoded = gzip.decompress(base64.b64decode(msg_encoded))
    msg = json.loads(msg_decoded)
    dupi_flowlog2pdu(msg)
