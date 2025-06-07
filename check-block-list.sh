#!/bin/bash

source_switch="$1"
source_a="ABUSEIPDB"
source_a_scriptname="ABUSEIPDB-bulk-ip-check.sh"
source_m="MXTOOLBOX"
source_m_scriptname="MXTOOLBOX-check-block-list.sh"
source="$source_m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$source_switch" == "-a" ]]; then
    source="$source_a"
fi

if [[ "$source" == "$source_a" ]]; then
    echo "Using $source_a as source."
    echo ""

    # Source the snort-monitor configuration file

    FNAME_CONFIG="snort-monitor.conf"
    export SCRIPT_DIR FNAME_CONFIG
    if [[ -f "$SCRIPT_DIR/${FNAME_CONFIG}" ]]; then
        source "$SCRIPT_DIR/${FNAME_CONFIG}"
    else
        echo "Configuration file ${FNAME_CONFIG} not found in $SCRIPT_DIR" >&2
    fi

    # Determine input and output filenames
    timestamp=$(date +"_%Y%m%d_%I%M%P")
    IN_FILE="$CONSOLIDATED_FILE"
    CD_FILE_BASE=$(basename "$CONSOLIDATED_FILE")
    OUT_FILE="$SCRIPT_DIR/${CD_FILE_BASE%.*}${timestamp}.csv"

    exec "$SCRIPT_DIR/$source_a/$source_a_scriptname" "$IN_FILE" "$OUT_FILE"

else
    echo "Using $source_m as source."
    echo ""

    exec "$SCRIPT_DIR/$source_m/$source_m_scriptname"
fi
