#!/bin/bash

# Constants
CONFIDENCE_THRESHOLD=0
REPORTS_THRESHOLD=9
WHITELIST_FILE="$HOME/.snort-monitor/whitelist.txt"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCRIPT_DIR
if [[ -f "$SCRIPT_DIR/snort-monitor.conf" ]]; then
  source "$SCRIPT_DIR/snort-monitor.conf"
fi

filter_ips() {
  local csv_content="$1"
  printf '%s\n' "$csv_content" | awk -F',' -v conf="$CONFIDENCE_THRESHOLD" -v rep="$REPORTS_THRESHOLD" '
    NR == 1 { next }  # Skip header row
    # Skip rows where the 2nd field contains ERROR (rate limit messages)
    $2 ~ /ERROR:/ { next }
    {
      gsub(/^"|"$/, "", $2)
      gsub(/^"|"$/, "", $3)
      if (($2+0) <= conf && ($3+0) <= rep) {
        print $1
      }
    }
  '
}

# STEP 1: Check if any IPs in the block list are safe according to MXTOOLBOX
echo "================================================================================================================================"
echo "extract-good-ips-from-block-list.sh started at $(date)"
echo "Checking the current block list with MXTOOLBOX..."
$SCRIPT_DIR/check-list.sh "--block-list" "-m"
latest_delta_file=$(find "$SCRIPT_DIR" -maxdepth 1 -name "ip-whitelist_delta_candidate_*" -type f -printf "%T@ %p\n" | sort -n | tail -1 | cut -d' ' -f2-)
delta_line_count=$(wc -l <"$latest_delta_file")
if [[ $delta_line_count -eq 0 ]]; then
  echo "No IPs were found in the block list that MXTOOLBOX considers safe. Exiting."
  echo "================================================================================================================================"
  exit 0
else
  echo "Created ${delta_line_count}-long list of IPs from the block-list that MXTOOLBOX considers safe: $latest_delta_file"
  echo "Content follows:"
  cat "$latest_delta_file"

  # STEP 2: Run the ABUSEIPDB bulk IP check on the latest delta file
  echo "--------------------------------------------------------------------------------------------------------------------------------"
  echo "Running ABUSEIPDB bulk IP check on these IPs to confirm that they are safe..."
  csv_file="${latest_delta_file%.*}.csv"
  $SCRIPT_DIR/ABUSEIPDB/ABUSEIPDB-bulk-ip-check.sh "$latest_delta_file" "$csv_file"
  sed -i '/^$/d' "$csv_file"
  CSV_line_count=$(wc -l <"$csv_file")
  if [[ $CSV_line_count -eq 0 ]]; then
    echo "No IPs were found in the ABUSEIPDB assessment. Exiting."
    echo "================================================================================================================================"
    exit 0
  else
    echo "Created ${CSV_line_count}-row CSV file containing the ABUSEIPDB risk assessment: $csv_file"
    ABUSEIPDB_assessment="$(<"$csv_file") | sort"
    echo "Content follows:"
    printf '%s\n' "$ABUSEIPDB_assessment"

    # STEP 3: Filter the IPs based on the ABUSEIPDB assessment and thresholds
    echo "--------------------------------------------------------------------------------------------------------------------------------"
    echo "Filtering IPs based on ABUSEIPDB assessment and thresholds of max $CONFIDENCE_THRESHOLD confidence and max $REPORTS_THRESHOLD reports..."
    filtered_ips="$(filter_ips "$ABUSEIPDB_assessment")"

    # STEP 4: Add the filtered IPs to the whitelist file, backing it up first
    echo "--------------------------------------------------------------------------------------------------------------------------------"
    timestamp=$(date +"_%Y%m%d_%I%M%P")
    archived_WHITELIST_FILE="${WHITELIST_FILE%.*}_archived_${timestamp}.txt"
    cat "$WHITELIST_FILE" | grep -v '^$' >"$archived_WHITELIST_FILE"
    FILTERED_IP_line_count=$(echo "$filtered_ips" | sed '/^$/d' | wc -l)
    if [[ $FILTERED_IP_line_count -eq 0 ]]; then
      echo "No IPs were found that match the criteria. Exiting."
      echo "================================================================================================================================"
      exit 0
    else
      echo "The following $FILTERED_IP_line_count IP(s) are considered safe and will be added to the whitelist file:"
      printf '%s\n' "$filtered_ips" | tee -a "$WHITELIST_FILE"

      # STEP 5: Sort and remove duplicates from the whitelist file
      TEMP_FILE=$(mktemp)
      sort "$WHITELIST_FILE" | uniq | grep -v '^$' >"$TEMP_FILE"
      WHITELIST_line_count=$(wc -l <"$TEMP_FILE")
      if [[ $WHITELIST_line_count -eq 0 ]]; then
        echo "No IPs left in the whitelist after filtering. Exiting."
        echo "================================================================================================================================"
        rm -f "$TEMP_FILE"
        exit 0
      else
        cat "$TEMP_FILE" >"$WHITELIST_FILE"
        rm -f "$TEMP_FILE"
        echo "--------------------------------------------------------------------------------------------------------------------------------"
        echo "Created new whitelist with $WHITELIST_line_count IPs. The old whitelist file has been backed up as $archived_WHITELIST_FILE"
        echo "extract-good-ips-from-block-list.sh completed successfully."
        echo "================================================================================================================================"
      fi
    fi
  fi
fi
