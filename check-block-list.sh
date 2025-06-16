#!/bin/bash
# -----------------------------------------------------------------------------
# check-block-list.sh
#
# This script checks a block list using a specified reputational source.
#
# Usage:
#   ./check-block-list.sh [-a | -m]
#
# Options:
#   -a    Use ABUSEIPDB as the source for checking the block list.
#   -m    Use MXTOOLBOX as the source for checking the block list.
#
# Description:
#   The script validates the input argument to ensure a valid source switch
#   is provided. It then calls the 'check-list.sh' script located in the same
#   directory, passing the '--block-list' flag and the selected source switch.
#
# Example:
#   ./check-block-list.sh -a
#   ./check-block-list.sh -m
# -----------------------------------------------------------------------------

SOURCE_SWITCH="$1" # can be -a for ABUSEIPDB or -m for MXTOOLBOX
LIST_TO_CHECK="--block-list"

if [[ "$SOURCE_SWITCH" != "-a" && "$SOURCE_SWITCH" != "-m" ]]; then
    echo "Usage: $0 [-a | -m]"
    echo "  -a: Use ABUSEIPDB as source."
    echo "  -m: Use MXTOOLBOX as source."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
$SCRIPT_DIR/check-list.sh "$LIST_TO_CHECK" "$SOURCE_SWITCH" 
