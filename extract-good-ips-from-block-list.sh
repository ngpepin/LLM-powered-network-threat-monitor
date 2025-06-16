#!/bin/bash
# shellcheck disable=SC1091
# shellcheck disable=SC2002
# shellcheck disable=SC2086

# extract-good-ips-from-block-list.sh
# -----------------------------------
# This script automates the process of extracting "good" (safe) IP addresses from a block list by cross-referencing with MXTOOLBOX and ABUSEIPDB,
# and updating a whitelist accordingly.
#
# Workflow Overview:
# ------------------
# 1. **Configuration & Setup**
#   - Loads configuration from `snort-monitor.conf` if present.
#   - Sets thresholds for confidence and reports from ABUSEIPDB.
#   - Defines file paths and formatting helpers.
#
# 2. **MXTOOLBOX Check**
#   - Runs `check-list.sh` to identify IPs in the block list that MXTOOLBOX considers safe.
#   - Outputs a delta file of candidate IPs.
#
# 3. **ABUSEIPDB Bulk Check**
#   - Runs a bulk IP check on the candidate IPs using ABUSEIPDB.
#   - Produces a CSV file with risk assessments for each IP.
#
# 4. **Filtering**
#   - Filters IPs from the CSV based on configured thresholds for confidence and number of reports.
#   - Only IPs with confidence and reports below or equal to the thresholds are considered safe.
#
# 5. **Whitelist Update**
#   - Backs up the current whitelist.
#   - Adds new, filtered safe IPs to the whitelist, ensuring uniqueness and sorting.
#   - Updates a CSV for manual analysis.
#   - Reports changes and cleans up temporary files.
#
# Functions:
# ----------
# - `filter_ips`: Filters CSV content for IPs meeting the safety criteria.
# - `sep_dashes`, `sep_double`: Print separator lines for output formatting.
#
# Variables:
# ----------
# - `CONFIDENCE_THRESHOLD`: Maximum allowed confidence of abuse (default: 0).
# - `REPORTS_THRESHOLD`: Maximum allowed number of abuse reports (default: 9).
# - `WHITELIST_FILE`: Path to the whitelist file.
# - `separator_characters`: Width for separator lines.
#
# Exit Conditions:
# ----------------
# - No safe IPs found by MXTOOLBOX or ABUSEIPDB.
# - No IPs meet the filtering criteria.
# - Whitelist remains unchanged after processing.
#
# Usage:
# ------
# Run this script as part of the snort-monitor suite to maintain an up-to-date whitelist of safe IPs, automatically cross-checked against external threat intelligence sources.
#

# Constants
CONFIDENCE_THRESHOLD=3
REPORTS_THRESHOLD=9
WHITELIST_FILE="$HOME/.snort-monitor/whitelist.txt"
separator_characters=155

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

sep_dashes() {
  printf '%*s\n' "$separator_characters" '' | tr ' ' '-'
}
sep_double() {
  printf '%*s\n' "$separator_characters" '' | tr ' ' '='
}

WHITELIST_start_count=$(cat "$WHITELIST_FILE" | sed '/^$/d' | wc -l)

# STEP 1: Check if any IPs in the block list are safe according to MXTOOLBOX
sep_double # ================
echo "extract-good-ips-from-block-list.sh started at $(date)"
echo "Checking the current block list with MXTOOLBOX..."
$SCRIPT_DIR/check-list.sh "--block-list" "-m"
latest_delta_file=$(find "$SCRIPT_DIR" -maxdepth 1 -name "ip-whitelist_delta_candidate_*" -type f -printf "%T@ %p\n" | sort -n | tail -1 | cut -d' ' -f2-)
delta_line_count=$(wc -l <"$latest_delta_file")
if [[ $delta_line_count -eq 0 ]]; then
  echo "No IPs were found in the block list that MXTOOLBOX considers safe. Exiting."
  sep_double # ================
  exit 0
else
  echo "Created ${delta_line_count}-long list of IPs from the block-list that MXTOOLBOX considers safe: $latest_delta_file"
  echo "Content follows:"
  cat "$latest_delta_file"

  # STEP 2: Run the ABUSEIPDB bulk IP check on the latest delta file
  sep_dashes # ----------------
  echo "Running ABUSEIPDB bulk IP check on these IPs to confirm that they are safe..."
  csv_file="${latest_delta_file%.*}.csv"

  $SCRIPT_DIR/ABUSEIPDB/ABUSEIPDB-bulk-ip-check.sh "$latest_delta_file" "$csv_file"
  sed -i '/^$/d' "$csv_file"
  CSV_line_count=$(cat "$csv_file" | tail -n +2 | wc -l)
  if [[ $CSV_line_count -eq 0 ]]; then
    echo "No IPs were found in the ABUSEIPDB assessment. Exiting."
    sep_double # ================
    exit 0
  else
    echo "Created ${CSV_line_count}-row CSV file containing the ABUSEIPDB risk assessment: $csv_file"
    ABUSEIPDB_assessment="$(cat "$csv_file" | tail -n +2 | sort)"
    echo "Content follows:"
    printf '%s\n' "$ABUSEIPDB_assessment"

    # STEP 3: Filter the IPs based on the ABUSEIPDB assessment and thresholds
    sep_dashes # ----------------
    echo "Filtering IPs based on ABUSEIPDB assessment and thresholds of maximum $CONFIDENCE_THRESHOLD confidence of abuse"
    echo "and maximum $REPORTS_THRESHOLD reports of abuse..."
    filtered_ips="$(filter_ips "$ABUSEIPDB_assessment")"

    # STEP 4: Add the filtered IPs to the whitelist file, backing it up first
    sep_dashes # ----------------
    FILTERED_IP_line_count=$(echo "$filtered_ips" | sed '/^$/d' | wc -l)
    if [[ $FILTERED_IP_line_count -eq 0 ]]; then
      echo "No IPs were found that match the criteria. Exiting."
      sep_double # ================
      exit 0
    else

      TEMP_FILE=$(mktemp)
      cat "$WHITELIST_FILE" >"$TEMP_FILE"
      echo "" >>"$TEMP_FILE"

      # STEP 5: Print and add the filtered IPs to the temporary file which contains the current whitelist, then sort and remove duplicates
      echo "The following $FILTERED_IP_line_count IP(s) are considered safe by ABUSEIPDB and will be added to the whitelist file"
      echo "(but only if they are NEW):"
      printf '%s\n' "$filtered_ips" | tee -a "$TEMP_FILE"
      TEMP_FILE_2=$(mktemp)
      cat "$TEMP_FILE" | sed '/^$/d' | sort | uniq >"$TEMP_FILE_2"
      WHITELIST_end_count=$(cat "$TEMP_FILE_2" | wc -l)
      rm -f "$TEMP_FILE"

      # Backup the current whitelist file
      timestamp=$(date +"_%Y%m%d_%I%M%P")
      archived_WHITELIST_FILE="${WHITELIST_FILE%.*}_archived_${timestamp}.txt"
      cat "$WHITELIST_FILE" >"$archived_WHITELIST_FILE"

      if [[ $WHITELIST_end_count -eq 0 ]]; then
        echo "No IPs are left in the whitelist after filtering. Exiting."
        echo "" >"$SCRIPT_DIR/ip-whitelist_latest.csv"
      else
        difference=$((WHITELIST_end_count - WHITELIST_start_count))
        if [[ $difference -gt 0 ]]; then
          echo "Created a new whitelist with a net addition of $difference unique IP(s). These new IP(s) follow:"
          diff "$WHITELIST_FILE" "$TEMP_FILE_2" | grep '^> ' | sed 's/^> //'
          cat "$TEMP_FILE_2" >"$WHITELIST_FILE"
          cat "$WHITELIST_FILE" >"$SCRIPT_DIR/ip-whitelist_latest.csv"
          echo "The old whitelist file has been backed up as $archived_WHITELIST_FILE"
          echo "'ip-whitelist_latest.csv' has been updated to support additional manual analysis"
        else
          echo "No change to whitelist file required. No backup created."
        fi
      fi
      rm -f "$TEMP_FILE_2"

      # Print termination message
      echo "extract-good-ips-from-block-list.sh completed successfully."
      sep_double # ================
    fi
  fi
fi
