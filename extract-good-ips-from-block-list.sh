#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Checking block-list..."
$SCRIPT_DIR/check-list.sh "--block-list" "-m" 

# Find the latest delta file and create a CSV filename from it
latest_delta_file=$(find "$SCRIPT_DIR" -maxdepth 1 -name "ip-whitelist_delta_candidate_*" -type f -printf "%T@ %p\n" | sort -n | tail -1 | cut -d' ' -f2-)
echo "Latest delta file created: $latest_delta_file"
csv_file="${latest_delta_file%.*}.csv"

# Run the ABUSEIPDB bulk IP check on the latest delta file
echo "Running ABUSEIPDB bulk IP check on the latest delta file..."
$SCRIPT_DIR/ABUSEIPDB/ABUSEIPDB-bulk-ip-check.sh "$latest_delta_file" "$csv_file"

echo "CSV file created: $csv_file"

# Pick the IPs with a reputation score of ___
# echo "Extracting good IPs from the CSV file..."
# echo "--> not implemented yet"

# create a new whitelist file with only the good IPs