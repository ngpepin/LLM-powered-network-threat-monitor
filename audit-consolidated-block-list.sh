#!/bin/bash
#
# =========================================================================================================================================
# audit-consolidated-block-list.sh - Script to check IP block list addresses against MXToolbox blacklists and generate whitelist candidates
# =========================================================================================================================================
#
# Overview:
# ----------
# This script processes a list of IP addresses, checks their blacklist status using the MXToolbox API, and generates a formatted report
# including DNS name, organization, and blacklist status. It also maintains a cache of blacklist lookups and
# outputs a list of whitelist candidate IPs.
#
# Key Features:
# -------------
# - Reads IP addresses from a consolidated block list file.
# - For each IP:
#     - Resolves DNS name (reverse lookup).
#     - Retrieves organization info via whois.
#     - Checks blacklist status using MXToolbox API (with caching).
# - Caches API responses and supports rebuilding cache from saved JSON responses.
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
# - check_mxtoolbox_blacklists: Checks an IP against MXToolbox blacklists, caches result.
# - redo_cache: Rebuilds the cache from saved JSON responses.
# - read_cache_status: Reads blacklist status for an IP from the cache.
# - print_whoami_list: Main function to process IPs, print results, and update whitelist candidates.
#
# Usage:
# ------
# - Run the script to process the consolidated block list and generate a report.
# - Use "-r" or "--redo-cache" to rebuild the cache from existing JSON files.
#
# Dependencies:
# -------------
# - bash, curl, jq, dig, whois, timeout, awk, sed, stat, tr, paste
#
# Output:
# -------
# - Formatted table of IP, DNS name, organization, and blacklist status.
# - Whitelist candidate IPs written to ip-whitelist_candidate.txt.
#
# Note:
# -----
# - Requires a valid MXToolbox API key.
# - Handles API/network errors and invalid responses gracefully.
#
#
# Shellcheck directives:
# shellcheck disable=SC2188
# shellcheck disable=SC2001
# shellcheck disable=SC2320
# shellcheck disable=SC2181
# shellcheck disable=SC2155
#

MXTOOBOX_API_KEY="" # MXToolbox API key - sourced from audit-consolidated-block-list.conf
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/audit-consolidated-block-list.conf"

CONSOLIDATED_FILE_SHARE="$SCRIPT_DIR/consolidated-block-list"                   # Path to the consolidated block list directory
CONSOLIDATED_FILE="$CONSOLIDATED_FILE_SHARE/consolidated-block-list.txt"        # Path to the consolidated block list file
CACHE_FILE="cache-ip-blacklist-status.txt"                                      # Path to the cache file
JSON_CACHE_DIR="$SCRIPT_DIR/mxtoolbox-cache"                                    # Directory for storing raw JSON API responses
WHITELIST_FILE="ip-whitelist_candidate.txt"                                     # Path to the outputted whitelist candidate file

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
    IFS=',' read -r -a items <<<"$1"
    widths=(18 45 35 80) # Increase widths as needed
    for i in {0..3}; do
        printf "%-*s" "${widths[i]}" "${items[i]:0:${widths[i]}}"
    done
    printf "\n"
}

# -----------------------------------------------------------------------------
# Function: check_mxtoolbox_blacklists
# -----------------------------------------------------------------------------
#
# Checks if a given IP address is listed on any MXToolbox blacklists, 
# using the MXToolbox API. Results are cached to avoid redundant API calls.
#
# Arguments:
#     $1 - The IP address to check.
#
# Environment Variables (must be set externally):
#     CACHE_FILE       - Path to the cache file storing previous lookup results.
#     JSON_CACHE_DIR   - Directory to store raw JSON API responses.
#
# Behavior:
#     - Checks the cache for a previous result for the IP.
#     - If cached, returns the cached status.
#     - If not cached, queries the MXToolbox API for blacklist status.
#     - Handles network/API errors and invalid responses gracefully.
#     - Parses the API response to determine if the IP is blacklisted or clean.
#     - Caches the result (including error states) for future lookups.
#     - Outputs a summary of the blacklist status.
#
# Output:
#     - Prints the blacklist status to stdout, prefixed with "Fresh:" if newly queried.
#     - Status can be "BLACKLISTED on <list>", "CLEAN", or an error message.
#
# Dependencies:
#     - curl
#     - jq
#
check_mxtoolbox_blacklists() {
    local ip="$1"

    local api_key="$MXTOOBOX_API_KEY"
    local cache_entry
    local status_string
    local ip_json_file="${JSON_CACHE_DIR}/${ip//./-}.json"

    # Check cache first
    cache_entry=$(grep "^$ip|" "$CACHE_FILE")
    if [ -n "$cache_entry" ]; then
        status_string=$(read_cache_status "$ip")
        echo "$status_string"
        return 0
    fi

    # API query
    response=$(curl -s -m 10 -X GET \
        "https://api.mxtoolbox.com/api/v1/lookup/blacklist/$ip" \
        -H "Authorization: $api_key" 2>&1)

    echo "$response" >"$ip_json_file"

    # Handle curl/network failure
    if [ $? -ne 0 ]; then
        status_string="API Error: Connection failed - ${response//|/-}"
    elif [ -z "$response" ]; then
        status_string="API Error: Empty response"
    elif ! jq -e . >/dev/null 2>&1 <<<"$response"; then
        status_string="API Error: Invalid JSON - ${response:0:100}"
    else
        # Schema check: must have at least Failed/Passed/Timeouts
        if ! jq -e '(.Failed or .Passed or .Timeouts)' <<<"$response" >/dev/null 2>&1; then
            status_string="API Error: Unexpected schema or content"
        else
            # Now check blacklist status
            if jq -e '.Failed and (.Failed | type == "array")' <<<"$response" >/dev/null; then
                if [ "$(jq '.Failed | length' <<<"$response")" -gt 0 ]; then
                    # Blacklisted
                    blacklists=$(jq -r '.Failed[]?.Name' <<<"$response" | tr '\n' ',')
                    bl_list="${blacklists%,}"
                    status_string="BLACKLISTED on $bl_list"
                else
                    status_string="CLEAN"
                fi
            else
                status_string="CLEAN"
            fi
        fi
    fi

    # Cache full result
    local now=$(date +%Y-%m-%dT%H:%M:%S)
    if [[ "$status_string" == "BLACKLISTED on "* ]]; then
        bl_abbrs=$(echo "$status_string" | sed 's/.* on //' | tr ',' '\n' | while read -r name; do
            echo "$name" | tr -cd '[:alnum:]' | tr '[:lower:]' '[:upper:]' | cut -c1-6
        done | paste -sd "," -)
        echo "$ip|$now|BLACKLISTED|$bl_abbrs" >>"$CACHE_FILE"
        echo "Fresh: BLACKLISTED by $(echo "$bl_abbrs" | sed 's/,/, /g')"
    elif [[ "$status_string" == "CLEAN" ]]; then
        echo "$ip|$now|CLEAN|" >>"$CACHE_FILE"
        echo "Fresh: CLEAN"
    else
        # Some kind of structured error
        echo "$ip|$now|$status_string|" >>"$CACHE_FILE"
        echo "Fresh: $status_string"
    fi
}

# -----------------------------------------------------------------------------
# Function: redo_cache
# -----------------------------------------------------------------------------
# Rebuilds the consolidated cache file from individual JSON result files from mxtoolbox.
#
# - Empties the existing cache file specified by $CACHE_FILE.
# - Iterates over all JSON files in $JSON_CACHE_DIR.
# - For each JSON file:
#     - Extracts the IP address from the filename (converts dashes to dots).
#     - Gets the file modification timestamp in ISO-like format.
#     - Reads the JSON response from the file.
#     - Skips files that are not valid JSON, not JSON objects, or flagged as API errors.
#     - Checks if the ".Failed" field is a valid array:
#         - If present and non-empty, treats the IP as blacklisted.
#             - Extracts blacklist names, abbreviates them, and joins as a comma-separated list.
#             - Writes a line to the cache: "IP|timestamp|BLACKLISTED|codes".
#         - If not, treats the IP as clean.
#             - Writes a line to the cache: "IP|timestamp|CLEAN|".
#
redo_cache() {
    >"$CACHE_FILE"

    for json_file in "$JSON_CACHE_DIR"/*.json; do
        [ -f "$json_file" ] || continue

        ip=$(basename "$json_file" .json | tr '-' '.')
        timestamp=$(stat -c %y "$json_file" 2>/dev/null | cut -d'.' -f1 | sed 's/ /T/')
        response=$(cat "$json_file")

        # Check if file contains valid JSON
        if ! jq -e . <<<"$response" >/dev/null 2>&1; then
            echo "Skipping invalid JSON: $json_file"
            continue
        fi

        # Check it's a proper JSON object (not a plain string or number)
        if jq -e 'type != "object"' <<<"$response" >/dev/null 2>&1; then
            echo "Skipping non-object JSON: $json_file"
            continue
        fi

        # Skip if explicitly flagged as API error
        if jq -e '.IsError == true' <<<"$response" >/dev/null 2>&1; then
            echo "Skipping API error: $json_file"
            continue
        fi

        # Check if .Failed is a valid array
        if jq -e '.Failed and (.Failed | type == "array")' <<<"$response" >/dev/null 2>&1; then
            failed_count=$(jq '.Failed | length' <<<"$response")
        else
            failed_count=0
        fi

        if [ "$failed_count" -gt 0 ]; then
            # IP is blacklisted
            failed=$(jq -r '.Failed[]?.Name' <<<"$response")
            bl_codes=()
            while read -r name; do
                abbr=$(echo "$name" | tr -cd '[:alnum:]' | tr '[:lower:]' '[:upper:]' | cut -c1-6)
                bl_codes+=("$abbr")
            done <<<"$failed"
            bl_list=$(
                IFS=','
                echo "${bl_codes[*]}"
            )
            echo "$ip|$timestamp|BLACKLISTED|$bl_list" >>"$CACHE_FILE"
        else
            # IP is clean
            echo "$ip|$timestamp|CLEAN|" >>"$CACHE_FILE"
        fi
    done
}

# -----------------------------------------------------------------------------
# Function: read_cache_status
# -----------------------------------------------------------------------------
# Reads the cache status of a given IP address from the cache file.
# Arguments:
#   $1 - The IP address to check in the cache.
# Outputs:
#   - If the IP is found and status is BLACKLISTED, prints: "Cached: BLACKLISTED by <list names>"
#   - If the IP is found and status is not BLACKLISTED, prints: "Cached: CLEAN"
#   - If the IP is not found, prints an empty string.
#
read_cache_status() {
    local ip="$1"
    if grep -q "^$ip|" "$CACHE_FILE"; then
        entry=$(grep "^$ip|" "$CACHE_FILE")
        status=$(echo "$entry" | cut -d'|' -f3)
        lists=$(echo "$entry" | cut -d'|' -f4 | sed 's/,/, /g')
        if [ "$status" = "BLACKLISTED" ]; then
            echo "Cached: BLACKLISTED by $lists"
        else
            echo "Cached: CLEAN"
        fi
    else
        echo ""
    fi
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
    format_fixed_columns "IP Address,DNS Name,Organization,Blacklist Status"
    format_fixed_columns "----------,--------,------------,------------------------------"

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

        local black_list_status=$(read_cache_status "$ip")

        # If not found in cache, do live check
        if [ -z "$black_list_status" ]; then
            black_list_status=$(check_mxtoolbox_blacklists "$ip")
        fi

        # If clean, add to whitelist candidate file
        if [[ "$black_list_status" == "Cached: CLEAN" || "$black_list_status" == "Fresh: CLEAN"* ]]; then
            echo "$ip" >>"$WHITELIST_FILE"
        fi

        format_fixed_columns "$ip,$dns_name,$org_info,$black_list_status"
    done <"$CONSOLIDATED_FILE"
}

# Main
if [[ "$1" == "-r" || "$1" == "--redo-cache" ]]; then
    echo "Rebuilding cache from JSON files..."
    redo_cache
fi

print_whoami_list
echo ""
echo "Candidate whitelist written to: $WHITELIST_FILE"
