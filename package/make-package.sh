#!/bin/bash
PACKAGE="dupi-lambda.zip"
cp ../dupi-lambda.py lambda_function.py
if zip -qm $PACKAGE lambda_function.py; then
    echo "Successfully created package $PACKAGE"
else
    echo "Failed to create package $PACKAGE"
fi
