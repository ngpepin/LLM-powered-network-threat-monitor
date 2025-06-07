#!/bin/bash
#
# =========================================================================================================================================
# MXTOOLBOX-check-block-list.sh - Script to check IP block list addresses and generate whitelist candidates
# =========================================================================================================================================
#
# Overview:
# ----------
# This script processes a list of IP addresses, checks their blacklist status using the script 'check_blacklist_status.sh', and generates
# a formatted report including DNS name, organization, and blacklist status. It also outputs a list of whitelist candidate IPs.
#
# Key Features:
# -------------
# - Reads IP addresses from a consolidated block list file.
# - Outputs a formatted table of results.
# - Writes clean IPs to a whitelist candidate file.
#
# Main Variables:
# ---------------
# - SCRIPT_DIR: Directory where the script resides.
# - CONSOLIDATED_FILE: Input file containing IP addresses to check.
# - CACHE_FILE: File storing cached blacklist lookup results.
# - JSON_CACHE_DIR: Directory for storing raw JSON API responses.
# - WHITELIST_FILE: Output file for whitelist candidate IPs.
#
# Main Functions:
# ---------------
# - format_fixed_columns: Formats and prints columns with fixed widths.
# - print_whoami_list: Main function to process IPs, print results, and update whitelist candidates.
#
# Usage:
# ------
# - Run the script to process the consolidated block list and generate a report.
#
# Output:
# -------
# - Formatted table of IP, DNS name, organization, and blacklist status.
# - Whitelist candidate IPs written to ip-whitelist_candidate.txt.
#
# Dependencies:
# -------------
# - bash, curl, jq, dig, whois, timeout, awk, sed, stat, tr, paste
#
# Note:
# -----
# - Handles API/network errors and invalid responses gracefully.
#
# Shellcheck directives:
# shellcheck disable=SC2188
# shellcheck disable=SC2001
# shellcheck disable=SC2320
# shellcheck disable=SC2181
# shellcheck disable=SC2155
#

CONSOLIDATED_FILE_SHARE="< set in config file >"                   # Path to the consolidated block list directory
CONSOLIDATED_FILE="< set in config file >"        # Path to the consolidated block list file
CACHE_FILE="< set in config file >"                                      # Path to the cache file
JSON_CACHE_DIR="< set in config file >"                                    # Directory for storing raw JSON API responses
WHITELIST_FILE="< set in config file >"                                     # Path to the outputted whitelist candidate file

# Source the configuration file
SCRIPT_SUB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; SCRIPT_SUB_DIR_NAME=$(basename "$SCRIPT_SUB_DIR"); SED_EXP="s#/$SCRIPT_SUB_DIR_NAME/*\$##" 
SCRIPT_DIR="$(echo "$SCRIPT_SUB_DIR" | sed $SED_EXP)"; FNAME_NO_EXT=$(basename "$0" | sed 's/\.[^.]*$//'); FNAME_CONFIG="${FNAME_NO_EXT}.conf"
export SCRIPT_DIR SCRIPT_SUB_DIR FNAME_CONFIG
if [[ -f "$SCRIPT_SUB_DIR/${FNAME_CONFIG}" ]]; then
    source "$SCRIPT_SUB_DIR/${FNAME_CONFIG}"
else
    echo "Configuration file ${FNAME_CONFIG} not found in $SCRIPT_SUB_DIR" >&2
    exit 1
fi

>"$WHITELIST_FILE" # Truncate the file at the start

# Create cache directory if it doesn't exist
mkdir -p "$JSON_CACHE_DIR" 2>/dev/null
[ -f "$CACHE_FILE" ] || touch "$CACHE_FILE"

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
    local -a widths=(20 30 55 100)
    local -a args=("$@")

    for i in "${!widths[@]}"; do
        local max_len=$((widths[i] - 2))
        printf "%-*s" "${widths[i]}" "${args[i]:0:max_len}"
    done
    printf "\n"
}

# -----------------------------------------------------------------------------
# Function: print_whoami_list
# -----------------------------------------------------------------------------
# Description:
#   Reads a list of IP addresses from the consolidated block list file and
#   prints a formatted table with the following columns:
#     - IP Address
#     - DNS Name (reverse DNS lookup)
#     - Organization (from whois information)
#     - Blacklist Status (from cache or live check)
#
#   For each IP address:
#     - Performs a reverse DNS lookup (with a 2-second timeout).
#     - Retrieves organization information from whois (with a 2-second timeout),
#       preferring the longest matching field among OrgName, org-name, descr,
#       owner, or netname.
#     - Checks the blacklist status using a cache or a live lookup if not cached.
#     - If the IP is found to be clean, adds it to the whitelist candidate file.
#     - Outputs the information in fixed-width columns.
#
# Globals:
#   CONSOLIDATED_FILE   - Path to the file containing the list of IP addresses.
#   WHITELIST_FILE      - Path to the file where clean IPs are appended.
#
# Dependencies:
#   - format_fixed_columns (function)
#   - read_cache_status (function)
#   - check_mxtoolbox_blacklists (function)
#   - dig, whois, awk, sed, timeout, head (commands)
#
# Usage:
#   print_whoami_list
#
print_whoami_list() {
    format_fixed_columns "IP Address" "DNS Name" "Organization" "Blacklist Status"
    format_fixed_columns "----------" "--------" "------------" "------------------------------"

    [ ! -f "$CONSOLIDATED_FILE" ] && return

    while read -r ip; do
        local dns_name=$(timeout 2 dig +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//')
        [ -z "$dns_name" ] && dns_name="N/A"

        # local org_info=$(timeout 2 whois "$ip" 2>/dev/null |
        #     awk -F':' '
        # $1 ~ /^(OrgName|descr|owner|netname)$/ {
        #     gsub(/^[ \t]+|[ \t]+$/, "", $2);
        #     if (length($2) > 5) {
        #         print $2;
        #         exit;
        #     }
        # }')
        local org_info=$(timeout 2 whois "$ip" 2>/dev/null |
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

        local black_list_status=$($SCRIPT_SUB_DIR/MXTOOLBOX-check_blacklist_status.sh "$ip")

        # If clean, add to whitelist candidate file
        if [[ "$black_list_status" == "Cached: CLEAN" || "$black_list_status" == "Fresh: CLEAN"* ]]; then
            echo "$ip" >>"$WHITELIST_FILE"
        fi

        format_fixed_columns "$ip" "$dns_name" "$org_info" "$black_list_status"

    done <"$CONSOLIDATED_FILE"
}

# Main
echo "Processing consolidated block list: $CONSOLIDATED_FILE"
echo -n "Number of records: "
cat "$CONSOLIDATED_FILE" | wc -l
echo 

print_whoami_list
echo ""
echo "Candidate whitelist written to: $WHITELIST_FILE"
