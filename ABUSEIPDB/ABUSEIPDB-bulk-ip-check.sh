#!/bin/bash
: '
bulk-ip-check.sh - Bulk IP Reputation Checker using AbuseIPDB API

This script checks a list of IP addresses against the AbuseIPDB API and outputs their reputation data to a CSV file.

Usage:
    ./bulk-ip-check.sh <ip_file> <output_path>

Arguments:
    ip_file      Path to a file containing one IP address per line.
    output_path  Path to the output CSV file.

Configuration:
    - The script expects a configuration file named "snort-monitor.conf" in the same directory.
    - The configuration file can override the following variables:
            ABUSEIPDB_API_KEY         # Your AbuseIPDB API key (must be exactly 80 characters)
            ABUSEIPDB_REPORT_MAX_AGE  # Max age in days for reports (default: 30)

Prerequisites:
    - jq: Command-line JSON processor (install with: sudo apt-get install jq)
    - curl: Command-line tool for making HTTP requests

Features:
    - Validates input arguments and configuration.
    - Checks each IP address using the AbuseIPDB API.
    - Outputs results in CSV format with the following columns:
            IP Address, % Confidence of Abuse, Total Reports within N days, ISP, Country Code, Domain, Distinct Users Reporting, Last Reported At
    - Handles and logs API errors per IP.
    - Removes temporary files after execution.

Notes:
    - Ensure your AbuseIPDB API key is kept secure and not hardcoded in public scripts.
    - The script will overwrite the output file if it already exists.
'
# Arguments
IP_FILE="$1"
OUTPUT_PATH="$2"

# Constants
ABUSEIPDB_API_KEY="< provided in ABUSEIPDB-bulk-ip-check.conf >"
ABUSEIPDB_REPORT_MAX_AGE=30

# Source the configuration file
SCRIPT_SUB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; SCRIPT_SUB_DIR_NAME=$(basename "$SCRIPT_SUB_DIR"); SED_EXP="s#/$SCRIPT_SUB_DIR_NAME/*\$##" 
SCRIPT_DIR="$(echo "$SCRIPT_SUB_DIR" | sed $SED_EXP)"; FNAME_NO_EXT=$(basename "$0" | sed 's/\.[^.]*$//'); FNAME_CONFIG="${FNAME_NO_EXT}.conf"
export SCRIPT_DIR SCRIPT_SUB_DIR FNAME_CONFIG
if [[ -f "$SCRIPT_SUB_DIR/${FNAME_CONFIG}" ]]; then
    source "$SCRIPT_SUB_DIR/${FNAME_CONFIG}"
else
    echo "Configuration file ${FNAME_CONFIG} not found in $SCRIPT_SUB_DIR" >&2
    exit 1
fi

# Check prerequisites
if ! command -v jq >/dev/null; then
    echo "jq is required but not installed. Please install it with: sudo apt-get install jq"
    exit 1
fi

if [[ ! -f "$IP_FILE" ]]; then
    echo "Input file not found: $IP_FILE"
    exit 1
fi

if [[ -z "$OUTPUT_PATH" ]]; then
    echo "No output file path provided."
    exit 1
fi

if [[ ${#ABUSEIPDB_API_KEY} -ne 80 ]]; then
    echo "Error: API key must be exactly 80 characters."
    echo "Key provided: $ABUSEIPDB_API_KEY"
    exit 1
fi

# Remove existing output file if it exists
[ -f "$OUTPUT_PATH" ] && rm "$OUTPUT_PATH"

# Header for CSV
echo "IP Address,% Confidence of Abuse,Total Reports within $MAX_AGE days,ISP,Country Code,Domain,Distinct Users Reporting,Last Reported At" >"$OUTPUT_PATH"

# Main processing loop
i=1
num_ips=$(wc -l <"$IP_FILE")

while IFS= read -r ip; do
    echo "[$i/$num_ips] Checking IP: $ip"

    curl -sG https://api.abuseipdb.com/api/v2/check \
        --data-urlencode "ipAddress=$ip" \
        -d maxAgeInDays=$ABUSEIPDB_REPORT_MAX_AGE \
        -H "Key: $ABUSEIPDB_API_KEY" \
        -H "Accept: application/json" \
        -o temp_ip_check.json

    # Check if the .data field exists
    if jq -e '.data' temp_ip_check.json >/dev/null; then
        jq -r '.data | "\(.ipAddress),\(.abuseConfidenceScore),\(.totalReports),\"\(.isp)\",\(.countryCode),\(.domain),\(.numDistinctUsers),\(.lastReportedAt)"' temp_ip_check.json | tee -a "$OUTPUT_PATH"
    else
        # Log error details
        echo "$ip,ERROR: $(jq -r '.errors[0].detail // "Unknown error"' temp_ip_check.json)" | tee -a "$OUTPUT_PATH"
    fi
    echo "--------------------------------------------------------------------------------------------------------------------------------------------"

    ((i++))
done <"$IP_FILE"

rm -f temp_ip_check.json
echo "Bulk check complete. Results saved to: $OUTPUT_PATH"
