#!/bin/bash
export LC_ALL=C.UTF-8

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

whitelist_with_clean_IPs_from_block_list=""
whitelist_file_with_only_clean=""

output=$($SCRIPT_DIR/MXTOOLBOX/MXTOOLBOX-check-list.sh --block-list)
whitelist_with_clean_IPs_from_block_list=$(echo "$output" | grep 'Candidate whitelist written to:' | awk -F': ' '{print $2}')
cat "$whitelist_with_clean_IPs_from_block_list" >> "$SCRIPT_DIR/whitelist.txt"
echo "Updated whitelist file with: $whitelist_with_clean_IPs_from_block_list"

output=$($SCRIPT_DIR/MXTOOLBOX/MXTOOLBOX-check-list.sh --whitelist)
whitelist_file_with_only_clean=$(echo "$output" | grep 'Candidate whitelist written to:' | awk -F': ' '{print $2}')
cat "$whitelist_file_validated_clean" >> "$SCRIPT_DIR/whitelist.txt"
echo "Updated whitelist file: $whitelist_file_with_only_clean"


