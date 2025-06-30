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
# Dependencies:
# - `xsv` (optional, for CSV rendering and processing) - https://github.com/BurntSushi/xsv?tab=readme-ov-file
# - `csvlook` (optional, for pretty-printing CSV content) - part of the `csvkit` package., e.g., sudo apt install csvkit
#
# Usage:
# ------
# Run this script as part of the snort-monitor suite to maintain an up-to-date whitelist of safe IPs, automatically cross-checked against external threat intelligence sources.
#

# Constants
CONFIDENCE_THRESHOLD=20
REPORTS_THRESHOLD=20
WHITELIST_FILE="$HOME/.snort-monitor/whitelist.txt"
separator_characters=155

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCRIPT_DIR
if [[ -f "$SCRIPT_DIR/snort-monitor.conf" ]]; then
  source "$SCRIPT_DIR/snort-monitor.conf"
fi

# Function:
# filter_ips()
#
# Filters IP addresses from CSV content based on confidence and reports thresholds.
#
# Arguments:
#   $1 - CSV content as a string. The CSV is expected to have a header row,
#        with at least three columns: IP, confidence, and reports.
#
# Environment Variables:
#   CONFIDENCE_THRESHOLD - Maximum allowed value for the confidence column.
#   REPORTS_THRESHOLD    - Maximum allowed value for the reports column.
#
# Behavior:
#   - Skips the header row.
#   - Skips rows where the second field contains "ERROR:" (e.g., rate limit messages).
#   - Removes surrounding double quotes from the confidence and reports fields.
#   - Prints the IP address (first column) if both confidence and reports are
#     less than or equal to their respective thresholds.
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

# Function:
# generate_integer_range_regex()
#
# Generates a regular expression matching integers within a specified range. Used to dynamically
# create regex patterns for use with xsv search filetering
#
# Usage:
#   generate_integer_range_regex MIN MAX
#
# Arguments:
#   MIN   The minimum integer value in the range (inclusive).
#   MAX   The maximum integer value in the range (inclusive).
#
# Description:
#   This function outputs a regular expression pattern that matches any integer
#   between MIN and MAX, inclusive. If MIN and MAX are equal, the pattern matches
#   only that single integer. The function validates that both arguments are integers
#   and that MIN is less than or equal to MAX.
#
# Returns:
#   0 on success, 1 on error (invalid input).
#
# Output:
#   Prints the generated regular expression to stdout.
#
# Examples:
#   generate_integer_range_regex 3 5
#     Output: ^(3|4|5)$
#
#   generate_integer_range_regex 7 7
#     Output: ^7$
#
generate_integer_range_regex() {
  local min=$1
  local max=$2

  # Validate input
  if ! [[ "$min" =~ ^-?[0-9]+$ ]] || ! [[ "$max" =~ ^-?[0-9]+$ ]]; then
    echo "Error: Both arguments must be integers" >&2
    return 1
  fi

  if ((min > max)); then
    echo "Error: Minimum must be less than or equal to maximum" >&2
    return 1
  fi

  # Special case: single number
  if ((min == max)); then
    echo "^$min$"
    return 0
  fi

  # Generate the regex pattern
  local pattern="^("

  for ((i = min; i <= max; i++)); do
    if ((i == max)); then
      pattern+="$i"
    else
      pattern+="$i|"
    fi
  done

  pattern+=")\$"

  echo "$pattern"
  return 0
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

  # STEP 2: Filter out IPs from mandatory blacklist
  blacklist_removed_tmp_file=$(mktemp)
  grep -vxFf "$BLACKLIST_FILE" "$latest_delta_file" >"$blacklist_removed_tmp_file"
  sed -i '/^$/d' "$blacklist_removed_tmp_file"
  blacklist_removed_line_count=$(cat "$blacklist_removed_tmp_file" | wc -l)
  if [[ $blacklist_removed_line_count -eq 0 ]]; then
    echo "No IPs were left after removing those in the blacklist file. Exiting."
    sep_double # ================
    rm -f "$blacklist_removed_tmp_file"
    exit 0
  elif [[ $blacklist_removed_line_count -lt $delta_line_count ]]; then
    net_count=$((delta_line_count - blacklist_removed_line_count))
    sep_dashes # ----------------
    echo "The same list but with $net_count IP(s) from the blacklist file ($BLACKLIST_FILE) removed (count=$blacklist_removed_line_count):"
    cat "$blacklist_removed_tmp_file"
  else
    echo "The list excludes IPs from the blacklist file ($BLACKLIST_FILE)."
  fi

  # STEP 3: Run the ABUSEIPDB bulk IP check on the remaining IPs
  sep_dashes # ----------------
  echo "Running ABUSEIPDB bulk IP check on these IPs to confirm that they are safe..."
  csv_file="${latest_delta_file%.*}.csv"
  $SCRIPT_DIR/ABUSEIPDB/ABUSEIPDB-bulk-ip-check.sh "$blacklist_removed_tmp_file" "$csv_file"
  rm -f "$blacklist_removed_tmp_file"
  sed -i '/^$/d' "$csv_file"
  CSV_line_count=$(cat "$csv_file" | tail -n +2 | wc -l)
  if [[ $CSV_line_count -eq 0 ]]; then
    echo "No IPs were found in the ABUSEIPDB assessment. Exiting."
    sep_double # ================
    exit 0
  else
    echo "Created ${CSV_line_count}-row CSV file containing the ABUSEIPDB risk assessment: $csv_file"
    echo "Content follows:"

    # Use xsv and csvlook to output the CSV content in a table format
    whole_table="$(xsv select 'IP Address','Domain','% Confidence of Abuse','Total Reports within  days' "$csv_file" |
      xsv sort -N -s '% Confidence of Abuse','Total Reports within  days' |
      xsv table | csvlook 2>/dev/null)"
    dash_width=$(($(head -n 1 <<<"$whole_table" | wc -m) - 3))
    dashes="+$(printf '%*s' "$dash_width" '' | tr ' ' '-')+"
    printf '%s\n%s\n%s\n' "$dashes" "$whole_table" "$dashes"
    alpha_whole_table="$(xsv select 'IP Address','Domain','% Confidence of Abuse','Total Reports within  days' "$csv_file" |
      xsv sort -N -s '% Confidence of Abuse','Total Reports within  days' |
      xsv sort -s 'Domain' |
      xsv table | csvlook 2>/dev/null)"
    echo ""
    echo "The same table sorted first by Domain follows:"
    printf '%s\n%s\n%s\n' "$dashes" "$alpha_whole_table" "$dashes"
    # OR, if xsv/csvlook not available, use cat "$ABUSEIPDB_assessment" | perl -pe 's/((?<=,)|(?<=^)),/ ,/g;' | column -t -s,
    # OR use printf '%s\n' "$ABUSEIPDB_assessment for vanilla output

    # STEP 4: Filter the IPs based on the ABUSEIPDB assessment and thresholds
    sep_dashes # ----------------
    echo "Filtering IPs based on ABUSEIPDB assessment and thresholds of maximum ${CONFIDENCE_THRESHOLD}% confidence of abuse and a maximum of $REPORTS_THRESHOLD discrete reports of abuse..."

    ABUSEIPDB_assessment="$(cat "$csv_file")"
    filtered_ips="$(filter_ips "$ABUSEIPDB_assessment")"
    FILTERED_IP_line_count=$(echo "$filtered_ips" | sed '/^$/d' | wc -l)

    if [[ $FILTERED_IP_line_count -eq 0 ]]; then
      echo "> no IPs were found that match those criteria. Exiting."
      sep_double # ================
      exit 0
    else
      # STEP 5: Add the filtered IPs to the whitelist file, backing it up first

      # Use xsv and csvlook to filter the CSV content and output in a nice format
      conf_filter_regex=$(generate_integer_range_regex 0 $CONFIDENCE_THRESHOLD)
      conf_reports_regex=$(generate_integer_range_regex 0 $REPORTS_THRESHOLD)
      filtered_table="$(xsv select 'IP Address','Domain','% Confidence of Abuse','Total Reports within  days' "$csv_file" |
        xsv sort -N -s '% Confidence of Abuse','Total Reports within  days' |
        xsv search -s '% Confidence of Abuse' "$conf_filter_regex" |
        xsv search -s 'Total Reports within  days' "$conf_reports_regex" | xsv table | csvlook 2>/dev/null)"
      dash_width=$(($(head -n 1 <<<"$filtered_table" | wc -m) - 3))
      dashes="+$(printf '%*s' "$dash_width" '' | tr ' ' '-')+"
      printf '%s\n%s\n%s\n' "$dashes" "$filtered_table" "$dashes"

      TEMP_FILE=$(mktemp)
      grep -vxFf "$BLACKLIST_FILE" "$WHITELIST_FILE" >"$TEMP_FILE"
      echo "" >>"$TEMP_FILE"

      # STEP 6: Print and add the filtered IPs to the temporary file which contains the current whitelist, then sort and remove duplicates
      sep_dashes # ----------------
      echo "The following $FILTERED_IP_line_count IP(s) are considered safe, given the criteria, by ABUSEIPDB and will be added to the whitelist file"
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
