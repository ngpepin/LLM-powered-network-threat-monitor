#!/bin/bash
# -----------------------------------------------------------------------------
# ntopng-log-to-csv.sh
#
# Converts an ntopng syslog-formatted log file to a CSV file for easier analysis.
#
# Usage:
#   ./ntopng-log-to-csv.sh [-r] <ntopng-log-file>
#
# Options:
#   -r                  Resolve hostnames to IP addresses using resolve-ntopng-log.sh
#   <ntopng-log-file>   Path to the ntopng log file to convert
#
# Description:
#   - Reads an ntopng syslog log file line by line.
#   - Optionally resolves hostnames to IP addresses if '-r' is specified.
#   - Extracts the date, time, message type, source, and destination from each log entry.
#   - Outputs a CSV file with the columns: Date, Time, Type, Source, Destination.
#   - The output CSV file is named after the input file, with a '.csv' extension.
#
# Dependencies:
#   - Bash shell
#   - awk, sed, grep, cut, date utilities
#   - resolve-ntopng-log.sh (if using the -r option)
#
# Example:
#   ./ntopng-log-to-csv.sh ntopng.log
#   ./ntopng-log-to-csv.sh -r ntopng.log
#
# -----------------------------------------------------------------------------
# Source the configuration file
LOCAL_USER_AND_GROUP=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCRIPT_DIR
if [[ -f "$SCRIPT_DIR/snort-monitor.conf" ]]; then
  source "$SCRIPT_DIR/snort-monitor.conf"
fi

if [[ $EUID -eq 0 ]]; then
  adjust_permissions=false
  echo "Script is running as root (or with sudo)."
else
  adjust_permissions=true
  if [ -z "$LOCAL_USER_AND_GROUP" ]; then
    LOCAL_USER_AND_GROUP="$(id -un):$(id -gn)"
  fi
  echo "Will adjust file permissions for non-root user: $LOCAL_USER_AND_GROUP"
fi

num_lines=999999

USAGE="Usage: $0 [-r] [-n <num lines>] <ntopng-log-file>"
resolve_DNS=false

SWITCH="$1"
if [ "$SWITCH" = "-r" ]; then
  resolve_DNS=true
  shift
fi

SWITCH="$1"
if [ "$SWITCH" = "-n" ]; then
  num_lines="$2"
  shift
  shift
fi

IN_FILE="$1"
if [ -z "$IN_FILE" ]; then
  IN_FILE="$NTOPNG_LOG"
fi

if [[ -z "$IN_FILE" ]] || sudo [ ! -f "$IN_FILE" ]; then
  echo "$USAGE"
  exit 1
fi

# copy contents of input file to temp file reversing order
temp_in_file=$(mktemp)
sudo tac "$IN_FILE" | head -n $num_lines | tee "$temp_in_file" >/dev/null
if [ "$adjust_permissions" = true ]; then
  sudo chown "$LOCAL_USER_AND_GROUP" "$temp_in_file" 2>/dev/null
fi

IN_FILE_NOEXT="${IN_FILE%.*}"
saved_IN_FILE="$IN_FILE"
IN_FILE="$temp_in_file"

if [ "$resolve_DNS" = true ]; then
  res_version="${IN_FILE_NOEXT}_IPs.log"
  if [ "$adjust_permissions" = true ]; then
    sudo chown "$LOCAL_USER_AND_GROUP" "$res_version" 2>/dev/null
  fi
  # if [ -f "$res_version" ]; then
  #  echo "Resolved file $res_version already exists. Using it."
  # else
  echo "Resolving hostnames in $saved_IN_FILE to IP addresses..."
  if [ ! -f "./resolve-ntopng-log.sh" ]; then
    echo "Error: resolve-ntopng-log.sh script not found in the current directory."
    exit 1
  fi
  sudo ./resolve-ntopng-log.sh "$IN_FILE" "$res_version"
  # fi
  IN_FILE="$res_version"
fi

timestamp=$(date +"_%Y%m%d_%I%M%P")
OUT_FILE="${IN_FILE_NOEXT}${timestamp}.csv"

if [ "$num_lines" -lt 999999 ]; then
  echo "Converting most recent $num_lines lines from $saved_IN_FILE to CSV format..."
else
  echo "Converting $saved_IN_FILE to CSV format..."
fi

# Write CSV header
HEADER='"Date","Time","Type","Source","Destination"'
echo "$HEADER" | sudo tee "$OUT_FILE" >/dev/null

if [ "$adjust_permissions" = true ]; then
  temp_out_file=$(mktemp)
  sudo cat "$IN_FILE" | tee "$temp_out_file" >/dev/null
  sudo chown "$LOCAL_USER_AND_GROUP" "$temp_out_file" 2>/dev/null
  sudo chmod 644 "$temp_out_file" 2>/dev/null
  echo "" >>"$temp_out_file"
  IN_FILE="$temp_out_file"
fi

line_counter=0
while IFS= read -r line; do
  # Skip empty lines
  [[ -z "$line" ]] && continue

  ((line_counter++))

  # Extract syslog date/time
  sys_month=$(echo "$line" | awk '{print $1}')
  sys_day=$(echo "$line" | awk '{print $2}')
  sys_time=$(echo "$line" | awk '{print $3}')
  year=$(date +"%Y") # Use current year

  # Format to YYYY-MM-DD and 12-hour time
  formatted_date=$(date -d "$sys_month $sys_day $year" +%Y-%m-%d)
  formatted_time=$(date -d "$sys_time" +%I:%M:%S\ %p)

  # Extract flow: source -> destination
  flow=$(echo "$line" | grep -oP '\[[^]]+ -> [^]]+\]' | sed 's/^\[//;s/\]$//')
  source=$(echo "$flow" | cut -d' ' -f1)
  destination=$(echo "$flow" | cut -d' ' -f3)

  # Extract message type (the part after the last bracket group)
  type=$(echo "$line" | sed -E 's/^.*\] *//; s/"//g; s/ for the client.*//; s/ \[ Blacklist.*//; s/ +$//')

  # Output CSV line to stdout and file
  echo "\"$formatted_date\",\"$formatted_time\",\"$type\",\"$source\",\"$destination\"" | sudo tee -a "$OUT_FILE" >/dev/null

  # Check if we reached the specified number of lines
  if [ "$line_counter" -ge "$num_lines" ]; then
    break
  fi

done <"$IN_FILE"

# Move the output file to the current directory if not running as root
if [ "$adjust_permissions" = true ]; then
  NEW_OUT_FILE="$(pwd)/$(basename "$OUT_FILE")"
  sudo mv -f "$OUT_FILE" "$NEW_OUT_FILE"
  OUT_FILE="$NEW_OUT_FILE"
  sudo chown "$LOCAL_USER_AND_GROUP" "$OUT_FILE" 2>/dev/null
  sudo chmod 644 "$OUT_FILE" 2>/dev/null
fi

echo "CSV written to $OUT_FILE"
