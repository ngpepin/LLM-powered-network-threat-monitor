#!/bin/bash

# convert-to-CIDR.sh
# ------------------
# This script summarizes a list of IP addresses into the smallest possible set of CIDR blocks.
#
# Usage:
#     ./convert-to-CIDR.sh <path-to-ip-list-file>
#
# Arguments:
#     <path-to-ip-list-file>   Path to a file containing a list of IP addresses (one per line).
#
# Behavior:
#     - Reads the input file, removes duplicates and empty lines.
#     - Summarizes the IP addresses into CIDR blocks using Python and the netaddr library.
#     - If the EXPLICIT_SLASH32 variable is set to true, all IPs (including single IPs) are output in CIDR notation (e.g., 1.2.3.4/32).
#     - If EXPLICIT_SLASH32 is false (default), single IPs are output without the /32 suffix.
#     - The summarized list is written to a new file in the same directory as the input, with "_CIDR" appended to the filename.
#
# Dependencies:
#     - Python 3
#     - netaddr Python library
#
# Exit Codes:
#     - 1: Missing argument, input file not found, or Python processing error.
#
# Example:
#     ./convert-to-CIDR.sh ips.txt
#
# Output:
#     Summarized IP list written to: <output-file-path>
# ---------------------------------------------------------------------------------

EXPLICIT_SLASH32=false
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <path-to-ip-list-file>"
    exit 1
fi

INPUT_FILE="$1"

if [ ! -f "$INPUT_FILE" ]; then
    echo "File not found: $INPUT_FILE"
    exit 1
fi

DIR=$(dirname "$INPUT_FILE")
FILE=$(basename "$INPUT_FILE")
EXT="${FILE##*.}"
NAME="${FILE%.*}"

if [[ "$FILE" == "$EXT" ]]; then
    OUTPUT_FILE="${DIR}/${NAME}_CIDR"
else
    OUTPUT_FILE="${DIR}/${NAME}_CIDR.${EXT}"
fi

if [ "$EXPLICIT_SLASH32" = true ]; then

    python3 - <<EOF >"$OUTPUT_FILE"
from netaddr import IPAddress, cidr_merge

# Read, clean, deduplicate
with open("$INPUT_FILE") as f:
    lines = f.readlines()

cleaned = sorted(set(line.strip() for line in lines if line.strip()))

# Parse and sort as IPAddress objects
try:
    ip_objs = sorted(set(IPAddress(ip) for ip in cleaned))
    cidrs = cidr_merge(ip_objs)
    for cidr in cidrs:
        print(cidr)
except Exception as e:
    import sys
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
EOF

else

    python3 - <<EOF >"$OUTPUT_FILE"
from netaddr import IPAddress, cidr_merge

# Read, clean, deduplicate
with open("$INPUT_FILE") as f:
    lines = f.readlines()

cleaned = sorted(set(line.strip() for line in lines if line.strip()))

# Parse and sort as IPAddress objects
try:
    ip_objs = sorted(set(IPAddress(ip) for ip in cleaned))
    cidrs = cidr_merge(ip_objs)
    for cidr in cidrs:
        if cidr.prefixlen == 32:
            print(str(cidr.ip))  # Just the IP, no /32
        else:
            print(cidr)
except Exception as e:
    import sys
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
EOF

fi

echo "Summarized IP list written to: $OUTPUT_FILE"
