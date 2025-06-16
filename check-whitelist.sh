#!/bin/bash
# -----------------------------------------------------------------------------
# Script Name: check-whitelist.sh
#
# Description:
#   This script is intended to be used as part of the snort-monitor project.
#   It performs operations related to checking or validating a whitelist.
#
# Usage:
#   ./check-whitelist.sh
#
# Notes:
#   - Ensure the script has execute permissions: chmod +x check-whitelist.sh
#   - Additional dependencies and configuration may be required.
# -----------------------------------------------------------------------------

SOURCE_SWITCH="$1" # can be -a for ABUSEIPDB or -m for MXTOOLBOX
LIST_TO_CHECK="--whitelist"

if [[ "$SOURCE_SWITCH" != "-a" && "$SOURCE_SWITCH" != "-m" ]]; then
    echo "Usage: $0 [-a | -m]"
    echo "  -a: Use ABUSEIPDB as source."
    echo "  -m: Use MXTOOLBOX as source."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
$SCRIPT_DIR/check-list.sh "$LIST_TO_CHECK" "$SOURCE_SWITCH" 
