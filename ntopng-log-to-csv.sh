#!/bin/bash
# Usage: ./ntopng-log-to-csv.sh <ntopng-log-file>

INPUT_FILE="$1"
OUTPUT_FILE="${INPUT_FILE%.log}.csv"

if [[ -z "$INPUT_FILE" || ! -f "$INPUT_FILE" ]]; then
  echo "Usage: $0 <ntopng-log-file>"
  exit 1
fi

# Write CSV header
HEADER='"Date","Time","Type","Source","Destination"'
echo "$HEADER" > "$OUTPUT_FILE"

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
  echo "\"$formatted_date\",\"$formatted_time\",\"$type\",\"$source\",\"$destination\"" >> "$OUTPUT_FILE"
done < "$INPUT_FILE"

echo "CSV written to $OUTPUT_FILE"
