#!/bin/bash

###############################################################################
# MXTOOLBOX-check-list.sh
#
# Description:
#   This script processes a list of IP addresses (either from a consolidated
#   block list or a whitelist) and prints a formatted table with the following
#   information for each IP:
#     - IP Address
#     - DNS Name (reverse DNS lookup)
#     - Organization (from whois information)
#     - Blacklist Status (from cache or live check)
#
#   The script supports two modes:
#     1. Scanning the consolidated block list (default)
#     2. Scanning the whitelist (with --whitelist or -w argument)
#
#   For each IP address, the script:
#     - Performs a reverse DNS lookup (with a 2-second timeout)
#     - Retrieves organization information from whois (with a 2-second timeout)
#     - Checks blacklist status using a cache or live lookup
#     - If the IP is clean, adds it to a candidate whitelist file
#     - Outputs the information in fixed-width columns
#
#   When scanning the block list, the script merges the candidate whitelist
#   with the existing whitelist, sorts, and deduplicates the entries.
#
# Usage:
#   ./MXTOOLBOX-check-list.sh [--whitelist|-w|--block-list|-b]
#
# Arguments:
#   --whitelist, -w    Scan the whitelist file instead of the block list
#   --block-list, -b   Scan the block list file (default)
#
# Configuration:
#   The script expects a configuration file named after itself with a .conf
#   extension (e.g., MXTOOLBOX-check-list.conf) in the same directory. This
#   file should define the following variables:
#     - CONSOLIDATED_FILE_SHARE: Path to the consolidated block list directory
#     - CONSOLIDATED_FILE: Path to the consolidated block list file
#     - CACHE_FILE: Path to the cache file
#     - JSON_CACHE_DIR: Directory for storing raw JSON API responses
#     - WHITELIST_FILE: Path to the whitelist file
#     - WHITELIST_CANDIDATE_FILE: Path to the outputted whitelist candidate file
#
# Dependencies:
#   - bash
#   - dig
#   - whois
#   - awk
#   - sed
#   - timeout
#   - head
#   - sort
#   - uniq
#   - mktemp
#
# Functions:
#   - format_fixed_columns: Formats and prints a string with fixed-width columns
#   - print_results: Processes IPs and prints formatted results
#
# Output:
#   - Prints a formatted table of IP information to stdout
#   - Writes candidate whitelist IPs to the specified file
#
###############################################################################
# Shellcheck directives:
# shellcheck disable=SC2188
# shellcheck disable=SC2001
# shellcheck disable=SC2320
# shellcheck disable=SC2181
# shellcheck disable=SC2155
#

CACHE_FILE="< set CACHE_FILE in config file >"                                     # Path to the cache file
CONSOLIDATED_FILE="< set CONSOLIDATED_FILE in config file >"                       # Path to the consolidated block list file
DNS_CACHE_FILE="< set DNS_CACHE_FILE in config file >"                             # Path to the DNS cache file
JSON_CACHE_DIR="< set WHITELIST_CANDIDATE_FILE in config file >"                   # Directory for storing raw JSON API responses
WHITELIST_CANDIDATE_FILE="< set WHITELIST_CANDIDATE_FILE in config file >"         # Path to the outputted whitelist candidate file
WHITELIST_FILE="< set WHITELIST_FILE in config file >"                             # Path to the whitelist file
WHOIS_CACHE_FILE="< set WHOIS_CACHE_FILE in config file >"                         # Path to the WHOIS cache file
WHITELIST_CANDIDATE_DELTA_FILE="< set WHITELIST_CANDIDATE_DELTA_FILE in config file >" 

# Source the configuration file
SCRIPT_SUB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_SUB_DIR_NAME=$(basename "$SCRIPT_SUB_DIR")
SED_EXP="s#/$SCRIPT_SUB_DIR_NAME/*\$##"
SCRIPT_DIR="$(echo "$SCRIPT_SUB_DIR" | sed $SED_EXP)"
FNAME_NO_EXT=$(basename "$0" | sed 's/\.[^.]*$//')
FNAME_CONFIG="${FNAME_NO_EXT}.conf"
export SCRIPT_DIR SCRIPT_SUB_DIR FNAME_CONFIG
if [[ -f "$SCRIPT_SUB_DIR/${FNAME_CONFIG}" ]]; then
    source "$SCRIPT_SUB_DIR/${FNAME_CONFIG}"
else
    echo "Configuration file ${FNAME_CONFIG} not found in $SCRIPT_SUB_DIR" >&2
    exit 1
fi

SCAN_FILE="$CONSOLIDATED_FILE" # Defaults to scanning block list file

>"$WHITELIST_CANDIDATE_FILE" # Truncate the whitelist candidate file at the start

# Create cache directory if it doesn't exist
mkdir -p "$JSON_CACHE_DIR" 2>/dev/null
[ -f "$CACHE_FILE" ] || touch "$CACHE_FILE"

# Initialize and clean DNS cache file
export LC_ALL=C.UTF-8
[ -f "$DNS_CACHE_FILE" ] || touch "$DNS_CACHE_FILE"
tmp_file=$(mktemp)
sort "$DNS_CACHE_FILE" | uniq >"$tmp_file"
cat "$tmp_file" >"$DNS_CACHE_FILE"
rm -f "$tmp_file"

[ -f "$WHOIS_CACHE_FILE" ] || touch "$WHOIS_CACHE_FILE"
tmp_file=$(mktemp)
sort "$WHOIS_CACHE_FILE" | uniq >"$tmp_file"
cat "$tmp_file" >"$WHOIS_CACHE_FILE"
rm -f "$tmp_file"

# -----------------------------------------------------------------------------
# Function: format_fixed_columns
# -----------------------------------------------------------------------------
# Formats and prints a string with fixed-width columns.
# Arguments:
#   $1 - Comma-separated string to format.
# Outputs:
#   - Prints the formatted string to stdout.
#   - Each column is padded to a fixed width and truncated if necessary.
#
format_fixed_columns() {
    local -a widths=(6 20 30 55 100)
    local -a args=("$@")

    for i in "${!widths[@]}"; do
        local max_len=$((widths[i] - 2))
        printf "%-*s" "${widths[i]}" "${args[i]:0:max_len}"
    done
    printf "\n"
}

# -----------------------------------------------------------------------------
# Function: print_results
# -----------------------------------------------------------------------------
# Description:
#     Processes a file containing a list of IP addresses, retrieves DNS names, organization information,
#     and blacklist status for each IP, and prints the results in formatted columns. If an IP is found
#     to be clean (not blacklisted), it is added to a whitelist candidate file.
#
# Parameters:
#     $1 - Path to the file containing the list of IP addresses to process.
#
# Behavior:
#     - Prints column headers for IP Address, DNS Name, Organization, and Blacklist Status.
#     - For each IP in the input file:
#         - Resolves the DNS name using `dig`.
#         - Retrieves organization info using `whois` and extracts relevant fields.
#         - Checks blacklist status by calling an external script.
#         - If the IP is clean, appends it to the whitelist candidate file.
#         - Prints the gathered information in fixed-width columns.
#
# Dependencies:
#     - format_fixed_columns: Function or command to print data in fixed-width columns.
#     - $SCRIPT_SUB_DIR/MXTOOLBOX-check_blacklist_status.sh: Script to check blacklist status.
#     - $WHITELIST_CANDIDATE_FILE: File path for storing whitelist candidates.
#
# Notes:
#     - Uses `timeout` to limit the execution time of `dig` and `whois` commands.
#     - Handles missing or empty data by substituting "N/A".
print_results() {
    local _scan_file="$1"

    [ ! -f "$_scan_file" ] && return

    local line_num=1

    format_fixed_columns "" "IP Address" "DNS Name" "Organization" "Blacklist Status"
    format_fixed_columns "" "----------" "--------" "------------" "------------------------------"

    local dns_name=""
    local org_info=""
    local black_list_status=""
    while read -r ip; do

        # DNS lookup with cache
        dns_name=$(awk -v ip="$ip" -F' ' '$1 == ip {print $2}' "$DNS_CACHE_FILE")
        if [ -z "$dns_name" ]; then
            dns_name=$(timeout 2 dig +short -x "$ip" 2>/dev/null | iconv -f utf-8 -t utf-8//IGNORE | head -1 | sed 's/\.$//')
            [ -z "$dns_name" ] && dns_name="N/A"
            echo "$ip $dns_name" >>"$DNS_CACHE_FILE"
        fi

        # WHOIS lookup with cache
        org_info=$(awk -v ip="$ip" -F' ' '$1 == ip { $1=""; sub(/^ /, "", $0); print $0 }' "$WHOIS_CACHE_FILE")
        if [ -z "$org_info" ]; then
            org_info=$(timeout 2 whois "$ip" 2>/dev/null | iconv -f utf-8 -t utf-8//IGNORE |
                awk -F':' '
        $1 ~ /^(OrgName|org-name|descr|owner|netname)$/ {
            gsub(/^[ \t]+|[ \t]+$/, "", $2);
            if (length($2) > maxlen) {
                maxlen = length($2);
                best = $2;
            }
        }
        END {
            if (length(best) > 0) {
                print best;
            } else {
                print "N/A";
            }
        }')

            [ -z "$org_info" ] && org_info="N/A"
            echo "$ip $org_info" >>"$WHOIS_CACHE_FILE"
        fi

        # Blacklist check
        black_list_status=$($SCRIPT_SUB_DIR/MXTOOLBOX-check_blacklist_status.sh "$ip")

        # Add clean IP to candidate whitelist
        if [[ "$black_list_status" == "Cached: CLEAN" || "$black_list_status" == "Fresh: CLEAN"* ]]; then
            echo "$ip" >>"$WHITELIST_CANDIDATE_FILE"
        fi

        format_fixed_columns "$line_num" "$ip" "$dns_name" "$org_info" "$black_list_status"

        ((line_num++))

    done <"$_scan_file"
}

ARG="$1"
if [[ "$ARG" == "--whitelist" || "$ARG" == "-w" ]]; then
    scan_whitelist=true
    echo "Scanning whitelist"
elif [[ "$ARG" == "--block-list" || "$ARG" == "-b" ]]; then
    scan_whitelist=false
    echo "Scanning block list"
else
    scan_whitelist=false
    echo "Defaulting to scanning block list"
fi

# Main
if [ "$scan_whitelist" = true ]; then
    SCAN_FILE="$WHITELIST_FILE"
    echo "Processing whitelist: $SCAN_FILE"
else
    SCAN_FILE="$CONSOLIDATED_FILE"
    echo "Processing consolidated block list: $SCAN_FILE"
fi
echo -n "Number of records: "
cat "$SCAN_FILE" | wc -l
echo
print_results "$SCAN_FILE"

# If scanning block list, then add candidate whitelisted IPs to the existing whitelist
if [ "$scan_whitelist" = false ]; then
    cat "$WHITELIST_CANDIDATE_FILE" >"$WHITELIST_CANDIDATE_DELTA_FILE"
    cat "$WHITELIST_FILE" >>"$WHITELIST_CANDIDATE_FILE"
    tmp_file=$(mktemp)
    sort "$WHITELIST_CANDIDATE_FILE" | uniq >"$tmp_file"
    cat "$tmp_file" >"$WHITELIST_CANDIDATE_FILE"
    rm -f "$tmp_file"
fi

echo ""
echo "Candidate whitelist written to: $WHITELIST_CANDIDATE_FILE"
