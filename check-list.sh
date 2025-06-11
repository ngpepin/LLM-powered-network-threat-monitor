#!/bin/bash

# check-list.sh - Script to check the reputation of IP addresses contained in either the block list or the whitelist
# using the ABUSEIPDB and MXTOOLBOX APIs as reputational sources.
#
# Usage:
#     ./check-list.sh [ --block-list | --whitelist ] [ -a | -m ]
#
# Arguments:
#     --block-list, -b   Check the block list (default if not specified).
#     --whitelist, -w    Check the whitelist.
#     -a                 Use the ABUSEIPDB API as the IP reputation source.
#     -m                 Use the MXTOOLBOX API (with caching) as the IP reputation source.
#
# Description:
#     This is a helper script that checks a list of IP addresses (either from the active block list or active whitelist)
#     against an external reputational sources (ABUSEIPDB or MXTOOLBOX, the latter being cached). 
#     It determines the mode and source based on command-line arguments, loads configuration if needed,
#     and invokes the appropriate checking script with the correct input and output files.
#
#     - For ABUSEIPDB, it sources a configuration file (snort-monitor.conf) and passes
#         the relevant input and output file paths to the ABUSEIPDB-bulk-ip-check.sh script.
#     - For MXTOOLBOX, it calls MXTOOLBOX-check-list.sh with the appropriate mode switch.
#
# Outputs:
#     - For ABUSEIPDB, the script will produce a CSV-formatted reputation report of either the whitelist or block list 
#       which can be ingested by other analysis tools.
#     - For MXTOOLBOX, the script will produce a new candidate whitelist file:
#           - If '--block-list' is specified, it will add IPs which MXTOOLBOX considers safe to the existing active whitelist, creating a new candidate.
#           - If '--whitelist' is specified, it will create a new candidate whitelist file trimmed of IPs which MXTOOLBOX considers unsafe.
#
# Environment Variables:
#     SCRIPT_DIR         Directory where the script is located.
#     FNAME_CONFIG       Name of the configuration file (snort-monitor.conf).
#
# Dependencies:
#     - ABUSEIPDB-bulk-ip-check.sh (for using ABUSEIPDB as the reputational source)
#     - MXTOOLBOX-check-list.sh (for using MXTOOLBOX as the reputational source)
#     - snort-monitor.conf
#

mode_switch="$1"   # can be --block-list or -b for checking blocklist, or --whitelist or -w for checking whitelist
source_switch="$2" # can be -a for ABUSEIPDB or -m for MXTOOLBOX as the reputational source

source_a="ABUSEIPDB"
source_a_scriptname="ABUSEIPDB-bulk-ip-check.sh"
source_m="MXTOOLBOX"
source_m_scriptname="MXTOOLBOX-check-list.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
user_error=false
check_block_list=true
source="$source_m"

# Interpret command line switches
if [[ "$mode_switch" == "--whitelist" || "$mode_switch" == "-w" ]]; then
    check_block_list=false
    source_m_parm="--whitelist"
    echo "Scanning whitelist."
elif [[ "$mode_switch" == "--block-list" || "$mode_switch" == "-b" ]]; then
    check_block_list=true
    source_m_parm="--block-list"
    echo "Scanning block list."
else
    user_error=true
fi
if [[ "$source_switch" == "-a" ]]; then
    source="$source_a"
elif [[ "$source_switch" == "-m" ]]; then
    source="$source_m"
else
    user_error=true
fi

# Provide usage help and exit
if [ "$user_error" = true ]; then
    echo "Check the reputation of IP addresses contained in either the block list or the whitelist using ABUSEIPDB or MXTOOLBOX"
    echo "Usage: $0 [ --block-list | --whitelist ] [-a | -m ]"
    echo "  use --block-list or -b to check block list"
    echo "  use --whitelist or -w to check whitelist"
    echo "  -a: Use ABUSEIPDB as the source for IP reputation"
    echo "  -m: Use MXTOOLBOX as the source for IP reputation"
    echo ""
    echo " With ABUSEIPDB, the script will produce a CSV-formatted reputation report which can be ingested by other analysis tools."
    echo " With MXTOOLBOX, the script will produce a new candidate whitelist file."
    exit 1
fi

if [[ "$source" == "$source_a" ]]; then

    # Use ABUSEIPDB as the reputational source
    echo "Using $source_a as the reputational source."
    echo ""

    # Source the snort-monitor configuration file
    FNAME_CONFIG="snort-monitor.conf"
    export SCRIPT_DIR FNAME_CONFIG
    if [[ -f "$SCRIPT_DIR/${FNAME_CONFIG}" ]]; then
        source "$SCRIPT_DIR/${FNAME_CONFIG}"
    else
        echo "Configuration file ${FNAME_CONFIG} not found in $SCRIPT_DIR" >&2
    fi

    timestamp=$(date +"_%Y%m%d_%I%M%P")

    # Determine input and output filenames
    if [ "$check_block_list" = false ]; then
        IN_FILE="$WHITELIST_FILE"
        OUT_FILE="${WHITELIST_FILE%.*}${timestamp}.csv"
    else
        IN_FILE="$CONSOLIDATED_FILE"
        CD_FILE_BASE=$(basename "$CONSOLIDATED_FILE")
        OUT_FILE="$SCRIPT_DIR/${CD_FILE_BASE%.*}${timestamp}.csv"
    fi

    # Execute the ABUSEIPDB script with the correct input and output files
    $SCRIPT_DIR/$source_a/$source_a_scriptname "$IN_FILE" "$OUT_FILE"

    echo "CSV reputation report file created: $OUT_FILE"

else
    # Use MXTOOLBOX as the reputational source
    echo "Using $source_m as the reputational source."
    echo ""

    # Execute the MXTOOLBOX script with the appropriate switch
    $SCRIPT_DIR/$source_m/$source_m_scriptname "$source_m_parm"

    latest_candidate_file=$(find "$SCRIPT_DIR" -maxdepth 1 -name "ip-whitelist_candidate_*" -type f -printf "%T@ %p\n" | sort -n | tail -1 | cut -d' ' -f2-)
    echo "Candidate whitelist created: $latest_candidate_file"

fi
# End of script
