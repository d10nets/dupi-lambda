# dupi-lambda <sub><sup>(export AWS Flow Logs via Lambda function to UDP server)</sup></sub>

#### >> Watch the DUPI live demo at [dupi1.d10nets.com](https://dupi1.d10nets.com/)<br> >> To monitor your own AWS Flow Logs please follow the instruction below (~20 min)

### DUPI Streaming AWS Flow Log Monitor

Monitor and analyze Amazon AWS Flow Logs from EC2 network interfaces, VPC subnets or entire VPCs on a dedicated AWS cloud server streaming network traffic statistics in real-time to your browser via DUPI Streaming AWS Flow Log Monitor (**DUPI** = **D**eep-**U**niversal-**P**rotocol-**I**nspection).

An AWS lambda function ([dupi-lambda.py](/dupi-lambda.py)) exports all relevant flow data to a dedicated cloud server to enable observation of aggregate protocol statistics across multiple virtual sites to view network traffic in your business as a 'whole' or at individual sites.

Analyze your network traffic in real-time for deep visibility into actual traffic patterns. Define detailed alerting rules per specific protocol field on various metrics as request rates, bps, pps, lengths, counts and geo-location info.

Explore network traffic at your sites easily and interactively from the comfort of your browser. Quickly switch protocols, fields, intervals and apply specific filter conditions in the web application for instant streaming results.

### Features
- **DUPI VIEW - Live Protocol Statistics**
  - View continuous live updates of network traffic statistics based on AWS flow logs at your sites in real-time per Source IP, Destination IP, Destination Port, Protocol, TCP Flags and other fields.
* **DUPI ALERT - Alerting Service**
  - Define detailed alerting rules for real-time network traffic conditions at your sites per field and various metrics as Packets-per-Second, Bits-per-Second, Tracking Time, Unique Field Counts, Geo Data and much more.
- **DUPI REPORT - Insights and Analysis**
  - View charts of top historical network traffic patterns at your sites for various intervals on Top Source IPs, Top Destination IPs, Top Destination Ports, Top Countries, Rates, Tracking times and much more.
* **DUPI GRAPH - Timeseries Graphs**
  - Graph historical network traffic statistics at your sites for 10 minutes, 1 hour, 1 day, 1 week and 1 month intervals on various metrics as Packets-per-Second, Bits-per-Second, Unique Field Counts and much more.
- **DUPI STORE - Historical Protocol Statistics**
  - Store historical network traffic statistics at your sites for 10 minute, 1 hour, 1day and 1 week intervals at your sites per Source IP, Destination IP, Destination Port, Protocol, TCP Flags and other fields.

---
### Screenshots

| DUPI REPORT                                      |
|--------------------------------------------------| 
| ![DUPI REPORT](/screenshots/dupi-report-flow.png)|

| DUPI VIEW                                        |
|--------------------------------------------------| 
| ![DUPI VIEW](/screenshots/dupi-view-flow.png)    |

| DUPI ALERT                                       |
|--------------------------------------------------| 
| ![DUPI ALERT](/screenshots/dupi-alert-flow.png)  |

| DUPI GRAPH                                       |
|--------------------------------------------------| 
| ![DUPI GRAPH](/screenshots/dupi-graph-flow.png)  |

| DUPI HOME                                        |
|--------------------------------------------------| 
| ![DUPI HOME](/screenshots/dupi-home.png)         |

Watch DUPI live at [dupi1.d10nets.com](https://dupi1.d10nets.com/). Get more info at [www.d10nets.com](https://www.d10nets.com/) or email us at [info@d10nets.com](mailto:info@d10nets.com).

---

### Instructions
Follow instructions below (~20 min) to export your AWS Flow Logs to a dedicated EC2 host running DUPI Streaming AWS Flow Log Monitor for observation of your network traffic statistics in real-time in your browser.
#### Clone repository
```
git clone https://github.com/d10nets/dupi-lambda.git
```
#### Export AWS Flow Logs
1. **Login to your Amazon AWS account in the [AWS Management Console](https://aws.amazon.com)**

2. **Enable AWS Flow Logs for EC2 network interfaces, EC2 subnets or VPCs**

   - **Create log group**
     - Select **Services → CloudWatch** and **Logs → Log Groups**
     - Click the **Action** dropdown and select **Create log group**
     - Provide **dupi-log-group** as input and click **Create log group**
     - Click **Never Expire** link of **dupi-log-group** and set **Retention** to **1 Day**
   
   - **Create flow log**
     - Select **Services → EC2** and **NETWORK & SECURITY → Network Interfaces** and choose a network interface
     - *OR / AND* select **Services → VPC** and **VIRTUAL PRIVATE CLOUD → Subnet** and choose a subnet
     - *OR / AND* select **Services → VPC** and **VIRTUAL PRIVATE CLOUD → Your VPCs** and choose a VPC
     - Click the **Flow Logs** tab and then click **Create flow log**
     - *ON INITIAL SETUP* click **Set Up Permissions** and in the **IAM Role** dropdown select **Create a new IAM Role**,
       provide **dupi-role** as input and click **Allow**
     - Set **Filter** to **Accept**, **Maximum aggregation interval** to **1 minute**, **Destination** to **Send to Cloudwatch Logs**,
       **Destination Log Group** to **dupi-log-group**, **IAM role** to **dupi-role** and **Format** to **AWS default format**
       and click **Create**

3. **Forward AWS Flow Logs to a dedicated EC2 monitoring host**  
   
   - **Create Lambda function**
     - Select **Services → Lambda** and click **Create Function**
     - Click **Author from scratch**, provide **dupi-lambda** as input and set **Runtime** as **Python 3.7**
     - Click **Choose or create an execution role** and select **Create a new role with basic Lambda permissions**
     - Click **Create Function**
     - In **Designer** click **dupi-lambda** and click **Add trigger**
     - In the **Trigger Configuration** dropdown select **Cloud Watch Logs**
     - Click the **Log group** dropdown and select **dupi-log-group**
     - For **Filter Name** provide **dupi-lambda-trigger** as input
     - Select **Enable Trigger** and click **Add**
     - Click **dupi-lambda** and scroll down to **Function Code**
     - In **Action** select **Upload a .zip file** and click **Upload**
     - Provide cloned **[dupi-lambda.zip](/package/dupi-lambda.zip)** file in **/package** directory for upload
 
   - **Set Environment Variables**
     - In **Environment Variables** click **Edit** and then click **Add Environment Variable** three times
     - On the first line for **Key** provide **DESTINATION_HOST** and for **Value** provide **dupi1.d10nets.com** as input
     - On the second line for **Key** provide **DESTINATION_PORT** and for **Value** provide **2055** as input
     - Optionally on the third line for **Key** provide **SITE_NAME** and for **Value** provide a descriptive name of your
       choice for your site (16 chars max), e.g. **john-doe-site**
     - Click **Save**

4. **Access DUPI Flow Log Monitor**

   - Go to **[dupi1.d10nets.com](https://dupi1.d10nets.com/)** to access DUPI Streaming AWS Flow Log Monitor
