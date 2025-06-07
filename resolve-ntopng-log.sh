#!/bin/bash
# resolve-ntopng-log.sh
# This script resolves domain names in an ntopng log file to their corresponding IP addresses.
# It reads the log file, resolves domain names using DNS, and writes the output to a specified file.
# It also caches resolved domain-to-IP mappings to avoid repeated lookups.
#
# Usage: ./resolve-ntopng-log.sh <ntopng-log-file> <output-file>
#

LOCAL_USER_AND_GROUP=""

# Determine the script directory and source the configuration file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCRIPT_DIR
if [[ -f "$SCRIPT_DIR/snort-monitor.conf" ]]; then
    source "$SCRIPT_DIR/snort-monitor.conf"
else
    echo "Configuration file snort-monitor.conf not found in $SCRIPT_DIR" >&2
fi

# Default DNS server and timeout
DNS_SERVER="8.8.8.8"                              # DNS Server used for resolution
DNS_TIMEOUT=1                                     # seconds for DNS resolution timeout
IN_FILE="$1"                                      # Input ntopng log file
OUT_FILE="$2"                                     # Output ntopng log formatted file with resolved entries
CACHE_FILE="$SCRIPT_DIR/resolve_ntopng_cache.txt" # Cache file for domain-to-IP mappings
CACHE_UPDATE_COUNT_FILE="$SCRIPT_DIR/resolve_ntopng_cache_updated.txt"
CACHE_UPDATE_COUNT=0             # Counter for cache refreshes
CACHE_UPDATE_COUNT_MAX_PURGE=200 # Maximum number of cache refreshes before purging cache contents

declare -A DNS_CACHE

# Function to check if a string is a domain name (not an IP)
is_domain() {
    [[ "$1" =~ [a-zA-Z] ]] && [[ "$1" =~ \. ]] && [[ ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

# Load cache from file into associative array
load_cache() {
    if [[ -f "$CACHE_FILE" ]]; then
        while IFS=$'\t' read -r domain ip; do
            [[ -n "$domain" && -n "$ip" ]] && DNS_CACHE["$domain"]="$ip"
        done <"$CACHE_FILE"
    fi

    # Load cache update count
    if [[ -f "$CACHE_UPDATE_COUNT_FILE" ]]; then
        read -r CACHE_UPDATE_COUNT <"$CACHE_UPDATE_COUNT_FILE"
    else
        CACHE_UPDATE_COUNT=0
    fi
}

# Append a new domain-to-IP mapping to cache file
append_to_cache() {
    echo -e "$1\t$2" >>"$CACHE_FILE"
}

# Resolve domain using DNS or cache
resolve_domain() {
    local domain=$1

    # Check cache first
    if [[ -n "${DNS_CACHE[$domain]}" ]]; then
        echo "${DNS_CACHE[$domain]}"
        return
    fi

    # Perform DNS lookup
    local ip
    if command -v timeout >/dev/null 2>&1; then
        ip=$(timeout $DNS_TIMEOUT dig +short @$DNS_SERVER "$domain" 2>/dev/null | grep -m 1 -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    else
        ip=$(dig +short @$DNS_SERVER "$domain" 2>/dev/null | grep -m 1 -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    fi

    # Use original domain if resolution failed
    ip="${ip:-$domain}"
    DNS_CACHE["$domain"]="$ip"
    append_to_cache "$domain" "$ip"
    echo "$ip"
}

# Process a single line, resolving domain names
process_line() {
    local line="$1"

    while read -r domain; do
        if ! is_domain "$domain" || [[ "$domain" =~ \.(in-addr|ip6)\.arpa$ ]]; then
            continue
        fi
        ip=$(resolve_domain "$domain")
        if [[ "$ip" != "$domain" ]]; then
            line="${line//$domain/$ip}"
        fi
    done < <(grep -oE '[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}' <<<"$line")

    echo "$line" >>"$OUT_FILE"
}

# Script entry point
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <ntopng-log-file> <output-file>"
    exit 1
fi

if [[ ! -f "$IN_FILE" ]]; then
    echo "Error: Input file $IN_FILE not found" >&2
    exit 1
fi

if [[ -z "$OUT_FILE" ]]; then
    OUT_FILE="${IN_FILE%.log}-resolved.log"
fi

touch "$OUT_FILE"
# Create cache if it doesn't exist
if [ ! -f "$CACHE_FILE" ]; then
    touch "$CACHE_FILE"
    if [ -n "$LOCAL_USER_AND_GROUP" ]; then
        sudo chown "$LOCAL_USER_AND_GROUP" "$CACHE_FILE"
    fi
fi
load_cache

while IFS= read -r line || [[ -n "$line" ]]; do
    process_line "$line"
done <"$IN_FILE"

# Save the cache back to the file unless it's time to purge
((CACHE_UPDATE_COUNT++))
if [ $CACHE_UPDATE_COUNT -gt $CACHE_UPDATE_COUNT_MAX_PURGE ]; then
    CACHE_UPDATE_COUNT=0
    echo "" >"$CACHE_FILE" # Clear the cache file
else
    TEMP_FILE=$(mktemp)
    sort "$CACHE_FILE" | uniq >"$TEMP_FILE"
    sudo mv -f "$TEMP_FILE" "$CACHE_FILE"
    if [ -n "$LOCAL_USER_AND_GROUP" ]; then
        sudo chown "$LOCAL_USER_AND_GROUP" "$CACHE_FILE"
    fi
fi
echo "$CACHE_UPDATE_COUNT" >"$CACHE_UPDATE_COUNT_FILE"
if [ -n "$LOCAL_USER_AND_GROUP" ]; then
    sudo chown "$LOCAL_USER_AND_GROUP" "$CACHE_UPDATE_COUNT_FILE"
fi
