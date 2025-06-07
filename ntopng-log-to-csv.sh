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

USAGE="Usage: $0 [-r] <ntopng-log-file>"
resolve_DNS=false

SWITCH="$1"
if [ -z "$SWITCH" ]; then
  echo "$USAGE"
  exit 1
fi
if [ "$SWITCH" = "-r" ]; then
  resolve_DNS=true
  shift
fi

IN_FILE="$1"
if [[ -z "$IN_FILE" || ! -f "$IN_FILE" ]]; then
  echo "$USAGE"
  exit 1
fi

IN_FILE_NOEXT="${IN_FILE%.*}"

if [ "$resolve_DNS" = true ]; then
  res_version="${IN_FILE_NOEXT}_IPs.log"
  if [ -f "$res_version" ]; then
    echo "Resolved file $res_version already exists. Using it."
  else
    echo "Resolving hostnames in $IN_FILE to IP addresses..."
    if [ ! -f "./resolve-ntopng-log.sh" ]; then
      echo "Error: resolve-ntopng-log.sh script not found in the current directory."
      exit 1
    fi
    exec "./resolve-ntopng-log.sh" "$IN_FILE" "$res_version"
  fi
  IN_FILE="$res_version"
fi

timestamp=$(date +"_%Y%m%d_%I%M%P")
OUT_FILE="${IN_FILE_NOEXT}${timestamp}.csv"

echo "Converting $IN_FILE to $OUT_FILE"

# Write CSV header
HEADER='"Date","Time","Type","Source","Destination"'
echo "$HEADER" >"$OUT_FILE"

while IFS= read -r line; do
  # Skip empty lines
  [[ -z "$line" ]] && continue

  # Extract syslog date/time
  sys_month=$(echo "$line" | awk '{print $1}')
  sys_day=$(echo "$line" | awk '{print $2}')
  sys_time=$(echo "$line" | awk '{print $3}')
  year="2025"

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
  echo "\"$formatted_date\",\"$formatted_time\",\"$type\",\"$source\",\"$destination\"" >>"$OUT_FILE"
done <"$IN_FILE"

echo "CSV written to $OUT_FILE"
