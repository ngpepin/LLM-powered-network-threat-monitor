#!/bin/bash
#
# =========================================================================================================================================
# MXTOOLSBOX check_blacklist_status.sh - Check if an IP address is blacklisted using MXToolbox API
# =========================================================================================================================================
#
# Overview:
# ----------
# This script checks if a given IP address is blacklisted using the MXToolbox API. It caches the results to avoid redundant API calls
# and supports reading from a cache file. It can operate in quiet mode (suppressing output) or boolean mode (returning true/false). 
# It can also rebuild the cache from saved JSON responses.
#
# Usage:
# ------
# - Use "-r" or "--redo-cache" to rebuild the cache from existing JSON files.
# - Use "-q" to suppress output, only return status.
# - Use "-b" to return true/false based on blacklist status.
#
# Main Functions:
# ---------------
# - check_mxtoolbox_blacklists: Checks an IP against MXToolbox blacklists, caches result.
# - redo_cache: Rebuilds the cache from saved JSON responses.
# - read_cache_status: Reads blacklist status for an IP from the cache.
#
# Key Features:
# -------------
# - Checks blacklist status using MXToolbox API (with caching).
# - Caches API responses and supports rebuilding cache from saved JSON responses.
# - Supports rebuilding cache from saved JSON responses.
#
# Main Variables:
# ---------------
# - SCRIPT_DIR: Directory where the script resides.
# - CACHE_FILE: File storing cached blacklist lookup results.
# - JSON_CACHE_DIR: Directory for storing raw JSON API responses.
#
# Note:
# -----
# - Requires a valid MXToolbox API key.
#
# Shellcheck directives:
# shellcheck disable=SC2188
# shellcheck disable=SC2001
# shellcheck disable=SC2320
# shellcheck disable=SC2181
# shellcheck disable=SC2155
#

MXTOOBOX_API_KEY="" # MXToolbox API key - sourced from configuration file

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

CACHE_FILE="$SCRIPT_DIR/cache-ip-blacklist-status.txt" # Path to the cache file
JSON_CACHE_DIR="$SCRIPT_DIR/mxtoolbox-cache"           # Directory for storing raw JSON API responses

# Create cache directory if it doesn't exist
mkdir -p "$JSON_CACHE_DIR" 2>/dev/null
[ -f "$CACHE_FILE" ] || touch "$CACHE_FILE"

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
#     - Prints the blacklist status to stdout, prefixed with "Fresh :" if newly queried.
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
        echo "Fresh : BLACKLISTED by $(echo "$bl_abbrs" | sed 's/,/, /g')"
    elif [[ "$status_string" == "CLEAN" ]]; then
        echo "$ip|$now|CLEAN|" >>"$CACHE_FILE"
        echo "Fresh : CLEAN"
    else
        # Some kind of structured error
        echo "$ip|$now|$status_string|" >>"$CACHE_FILE"
        echo "Fresh : $status_string"
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

if [ $# -lt 1 ]; then
    echo "Usage: $0 [-q|-b] <IP_ADDRESS>"
    exit 1
fi
if [[ ! -f "$CACHE_FILE" ]]; then
    echo "Cache file not found: $CACHE_FILE"
    exit 1
fi

quiet_mode=false
boolean_mode=false
if [[ "$1" == "-r" || "$1" == "--redo-cache" ]]; then
    echo "Rebuilding cache from JSON files..."
    redo_cache
    exit 0
elif [ "$1" = "--quiet" ] || [ "$1" = "-q" ]; then
    quiet_mode=true
    ip="$2"
elif [ "$1" = "--boolean" ] || [ "$1" = "-b" ]; then
    boolean_mode=true
    ip="$2"
else
    ip="$1"
fi

black_list_status=$(read_cache_status "$ip")

# If not found in cache, do live check
if [ -z "$black_list_status" ]; then
    black_list_status=$(check_mxtoolbox_blacklists "$ip")
fi

# Return results based on mode
if [[ "$black_list_status" == "Cached: CLEAN" || "$black_list_status" == "Fresh : CLEAN"* ]]; then
    if [ "$boolean_mode" = true ]; then
        echo "false"
    elif [ "$quiet_mode" = false ]; then
        echo "$black_list_status"
    fi
    exit 0
else
    if [ "$boolean_mode" = true ]; then
        echo "true"
    elif [ "$quiet_mode" = false ]; then
        echo "$black_list_status"
    fi
    exit 1
fi
