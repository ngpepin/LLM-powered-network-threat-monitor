#!/bin/bash
# Shellcheck directives
# shellcheck disable=SC2155
# shellcheck disable=SC2181
# shellcheck disable=SC1091
# shellcheck disable=SC2086
# shellcheck disable=SC2001
# shellcheck disable=SC1090
###############################################################################
#
# snort-monitor.sh
# -----------------------------------------------------------------------------
#
# Overview:
#   This script provides a comprehensive monitoring and automation solution for
#   correlating Snort and ntopng logs, generating threat analysis reports,
#   maintaining block lists for pfSense/pfBlockerNG, and serving a web-based
#   dashboard for real-time security visibility.
#
# Features:
#   - Loads configuration from an external .conf file for flexible deployment.
#   - Periodically analyzes Snort and ntopng logs, correlating events.
#   - Submits log data to an LLM API for advanced threat analysis and block list
#     generation, using customizable prompt templates.
#   - Generates HTML and PDF threat reports, including structured sections and
#     technical discussions.
#   - Maintains and consolidates block lists, applying whitelist filtering and
#     public IP validation.
#   - Serves a web dashboard with automatic refresh and cache control.
#   - Provides a secondary HTTP server for sharing consolidated block lists with the
#     pfSense firewall.
#   - Supports automatic whitelist updates at a scheduled time.
#   - Handles dependency installation, log rotation, and cleanup of old files.
#   - Implements randomized intervals for analysis to avoid predictable patterns.
#
# Main Components:
#   - Configuration loading and variable initialization.
#   - Dependency checks and installation.
#   - Web server setup for dashboard and block list sharing.
#   - Utility functions for encoding, escaping, and file management.
#   - Core functions:
#       * save_PDF_report: Generates PDF from HTML analysis.
#       * create_webpage: Builds the HTML dashboard.
#       * is_public_ip: Validates routable IPv4 addresses.
#       * consolidate_ips: Aggregates and filters block list IPs.
#       * update_analysis: Orchestrates log analysis, API calls, reporting, and
#         block list generation.
#       * calculate_perturbed_interval: Adds jitter to analysis intervals.
#       * update_whitelist_runner: Schedules daily whitelist updates.
#   - Background monitoring and cleanup logic.
#   - Main loop for periodic analysis and dashboard updates.
#
# Usage:
#   - Place this script and its .conf file in the same directory.
#   - Ensure required dependencies are installed (the script will attempt to
#     install missing ones).
#   - Configure paths, API credentials, and operational parameters in the .conf
#     file.
#   - Run the script as a service or in the background.
#
# Dependencies:
#   - bash, curl, jq, inotifywait, wkhtmltopdf, python3
#
# Author:
#   Nicolas Pepin
#
# License:
#   MIT License
#
###############################################################################

# Configuration variables THAT MUST BE OVERRIDDEN IN SNORT-MONITOR.CONF
SNORT_LOG="<provide in .conf file>"  # Path to the snort log file (sourced from snort-monitor.conf
NTOPNG_LOG="<provide in .conf file>" # Path to the ntopng log file (sourced from snort-monitor.conf)

# LLM (Large Language Model) parameters THAT MUST BE OVERRIDDEN IN SNORT-MONITOR.CONF
API_ENDPOINT='<provide in .conf file>' # API endpoint for the AI service
API_KEY="<provide in .conf file>"      # OpenAI API key
MODEL="<provide in .conf file>"        # Model to use for the AI service (e.g., gpt-4o)

# Default configuration variables *** THAT SHOULD BE OVERRIDDEN IN SNORT-MONITOR.CONF ***
UPDATE_INTERVAL=99999            # Interval to check for new logs (in seconds)
AUTO_UPDATE_WHITELIST_BOOL=false # Whether to automatically update the whitelist
AUTO_UPDATE_HOUR_1="02:00"       # Time of day to update the whitelist #1 (24-hour format, e.g., "14:30" for 2:30 PM)
AUTO_UPDATE_HOUR_2="14:00"       # Time of day to update the whitelist #2 (24-hour format, e.g., "14:30" for 2:30 PM)
LOCAL_USER_AND_GROUP=""          # Ensure output files are accessible to this user, if specified; override in snort-monitor.conf if you wish, e.g. "www-data:www-data"
DELETE_BLOCK_LISTS_AFTER=28      # Number of days to keep the block list files before deleting them

# MUST BE OVERRIDDEN IN SNORT-MONITOR.CONF
BLOCK_LIST_DIR="<provide in .conf file>"          # e.g., $SCRIPT_DIR/block-lists                               Directory to store block lists in
CONSOLIDATED_FILE_SHARE="<provide in .conf file>" # e.g., $SCRIPT_DIR/consolidated-block-list                   Consolidated block list directory (samba share)
CONSOLIDATED_FILE="<provide in .conf file>"       # e.g., $CONSOLIDATED_FILE_SHARE/consolidated-block-list.txt  Consolidated block list file
WHITELIST_FILE="<provide in .conf file>"          # e.g., $SCRIPT_DIR/ip-whitelist.txt                          IP whitelist file
REPORTS_DIR="<provide in .conf file>"             # e.g., $SCRIPT_DIR/reports                                   Directory to store PDF reports in
WEB_DIR="<provide in .conf file>"                 # e.g., /var/www/snort-monitor                               Directory for web files

#------------------------------------------------------------------------------

# pfSense-specific parameters THAT MUST BE OVERRIDDEN IN SNORT-MONITOR.CONF
INCLUDE_NTOPNG_LOGS=false             # Whether to include ntopng logs in the analysis
PFSENSE_DIR="<provide in .conf file>" # Directory where pfSense logs are stored
LOG_DIR="$PFSENSE_DIR/ ... "          # Directory for pfSense logs
ALT_LOG_DIR="$PFSENSE_DIR/ ... "      # Alternate directory for pfSense logs
SNORT_LOG="$LOG_DIR/snort.log"        # Snort log file
NTOPNG_LOG="$ALT_LOG_DIR/ntopng.log"  # ntopng log file

MONITOR_PFSENSE_THERMALS=false                         # Whether to monitor pfSense thermal sensors
PFSENSE_THERMALS_LOG="$SCRIPT_DIR/pfsense-thermal.log" # Path to the pfSense thermal log file
PFSENSE_THERMALS_INTERVAL=10                           # Interval to check pfSense thermal sensor (in seconds) - min is 10 sec

PFSENSE_RESTART=false        # Whether to restart pfSense
PFSENSE_RESTART_HOUR="05:00" # Time of day to restart pfSense

#------------------------------------------------------------------------------

# Prompt text THAT MUST BE OVERRIDDEN IN SNORT-MONITOR.CONF
read -r -d '' ANALYSIS_PROMPT_TEXT <<'EOF'
... <provide in .conf file> ...
EOF

# Prompt text THAT MUST BE OVERRIDDEN IN SNORT-MONITOR.CONF
read -r -d '' BLOCKLIST_PROMPT_TEXT <<'EOF'
... <provide in .conf file> ...
EOF

#------------------------------------------------------------------------------

# Interval and Pertubation variables
INTERVAL_PERTURBATION_MIN=0.8 # Minimum perturbation coefficient for interval
INTERVAL_PERTURBATION_MAX=1.4 # Maximum perturbation coefficient for interval
WEBPAGE_EXPIRATION_GRACE=10   # Grace period for webpage expiration allowing LLM API query/ies to take place (in seconds)

# Web server configuration
WEB_PORT=9999            # Port for the Analysis web server
LOG_LINES_TO_SHOW=120    # Number of log lines to provide to the LLM and show on the webpage
BLOCK_LIST_WEB_PORT=9998 # Port for the Block List web server

###############################################################################

# Source the configuration file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FNAME_NO_EXT=$(basename "$0" | sed 's/\.[^.]*$//')
FNAME_CONFIG="${FNAME_NO_EXT}.conf"
export SCRIPT_DIR FNAME_CONFIG
if [[ -f "$SCRIPT_DIR/${FNAME_CONFIG}" ]]; then
    source "$SCRIPT_DIR/${FNAME_CONFIG}"
else
    echo "Configuration file ${FNAME_CONFIG} not found in $SCRIPT_DIR" >&2
fi

###############################################################################

TIMESTAMP_FILE="/tmp/last_snort_check.time" # File to store the last check timestamp
LOG_FILE="/var/log/snort-monitor.log"       # Log file for the script

# Execute custom initialization code if exists
if [[ -f "$SCRIPT_DIR/custom-init.sh" ]]; then
    source "$SCRIPT_DIR/custom-init.sh" >/dev/null 2>&1
fi

# Variables to store last analysis and Snort/ntopng log content
last_analysis=""
last_log_content=""
last_response=""
last_update_time=""

# State variables, flag file and get/set functions to control the auto consolidation of block lists
skip_auto_consolidation=false
skip_auto_consolidation_flag_file="$(mktemp)"
disable_auto_consolidation() {
    log "Disabling auto consolidation of block lists"
    if [[ ! -f "$skip_auto_consolidation_flag_file" ]]; then
        skip_auto_consolidation_flag_file="$(mktemp)"
    else
        touch "$skip_auto_consolidation_flag_file"
    fi
    skip_auto_consolidation=false
}
enable_auto_consolidation() {
    log "Enabling auto consolidation of block lists"
    if [[ -f "$skip_auto_consolidation_flag_file" ]]; then
        rm -f "$skip_auto_consolidation_flag_file" >/dev/null 2>&1
    fi
    skip_auto_consolidation=false
}
is_auto_consolidation_enabled() {
    if [[ -f "$skip_auto_consolidation_flag_file" ]]; then
        skip_auto_consolidation=true
        log "Auto consolidation of block lists is disabled"
        return 0
    else
        skip_auto_consolidation=false
        log "Auto consolidation of block lists is enabled"
        return 1
    fi
}

pfsense_availability_message=""

# Create directories if they don't exist
mkdir -p "$WEB_DIR"
mkdir -p "$(dirname "$LOG_FILE")"
mkdir -p "$BLOCK_LIST_DIR"
mkdir -p "$REPORTS_DIR"
mkdir -p "$CONSOLIDATED_FILE_SHARE"

# Install dependencies if not available (except for Python, which is assumed to be installed)
if ! command -v wkhtmltopdf &>/dev/null; then
    sudo apt-get install wkhtmltopdf -y
fi
if ! command -v inotifywait &>/dev/null; then
    sudo apt-get install inotify-tools -y
fi
if ! command -v jq &>/dev/null; then
    sudo apt-get install jq -y
fi
if ! command -v curl &>/dev/null; then
    sudo apt-get install curl -y
fi

# Create a simple Python HTTP server with expiration header
expires_in_secs_with_max_grace_flt=$(echo "$UPDATE_INTERVAL * $INTERVAL_PERTURBATION_MAX + $WEBPAGE_EXPIRATION_GRACE" | bc)
expires_in_secs_with_max_grace=$(printf "%.0f" "$expires_in_secs_with_max_grace_flt")

cat <<EOF >"$WEB_DIR/server.py"
from http.server import SimpleHTTPRequestHandler, HTTPServer
from datetime import datetime, timedelta
import os

class CacheControlHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        # Set cache to expire 
        expires = datetime.utcnow() + timedelta(seconds=$expires_in_secs_with_max_grace)
        self.send_header("Expires", expires.strftime("%a, %d %b %Y %H:%M:%S GMT"))
        self.send_header("Cache-Control", "max-age=$expires_in_secs_with_max_grace, must-revalidate")
        SimpleHTTPRequestHandler.end_headers(self)
    
    def do_GET(self):
        # Redirect root to index.html
        if self.path == '/':
            self.path = '/index.html'
        # Disable directory listings
        if os.path.isdir(self.directory + self.path):
            self.path = '/index.html'
        return SimpleHTTPRequestHandler.do_GET(self)

def run(server_class=HTTPServer, handler_class=CacheControlHandler, port=9999):
    web_dir = os.path.join(os.path.dirname(__file__))
    os.chdir(web_dir)
    server_address = ('0.0.0.0', port)  
    httpd = server_class(server_address, handler_class)
    print(f"Starting server on 0.0.0.0:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
EOF

# Make the server executable
chmod +x "$WEB_DIR/server.py"

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >>"$LOG_FILE"
}

# Function to properly escape JSON strings
escape_json() {
    jq -Rs '[.]' | jq -r '.[0]'
}

# Function to escape HTML special characters
escape_html() {
    sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}

# Base64 encode a string (used for parameter passing in order to avoid issues with special characters)
encode() {
    local input="$*"
    if [[ -z "$input" ]]; then
        echo ""
    else
        echo -n "$input" | base64 | tr -d '\n'
    fi
}

# Base64 decode a string (used for parameter passing in order to avoid issues with special characters)
decode() {
    local input="$*"
    if [[ -z "$input" ]]; then
        echo ""
    else
        echo -n "$input" | base64 --decode 2>/dev/null || echo ""
    fi
}

# Function to remove leading and trailing backticks from a string
remove_backticks() {
    local string="$1"

    # Remove leading triple backticks (if they exist)
    local cleaned=$(echo "$string" | sed 's/^```//')
    # Remove trailing triple backticks (if they exist)
    cleaned=$(echo "$cleaned" | sed 's/```$//')

    echo "$cleaned" # Output: "Hello, world!"
}

start_web_server() {
    # create a temp file
    local temp_file=$(mktemp)
    while true; do
        log "Starting web server on 0.0.0.0:$WEB_PORT"
        cd "$WEB_DIR" && python3 ./server.py 2>>"$temp_file"
        log "Web server crashed, restarting..."
        log "Error log: $(cat "$temp_file")"
        sleep 5
    done
}

share_block_list_via_HTTP() {
    while true; do
        cd "$CONSOLIDATED_FILE_SHARE" ||
            {
                log "Failed to change directory to $CONSOLIDATED_FILE_SHARE"
                exit 1
            }
        python3 -m http.server 9998 --bind 0.0.0.0
        log "Block list web server crashed, restarting..."
        sleep 5
    done
}

# -----------------------------------------------------------------------------
# Function: save_PDF_report
# -----------------------------------------------------------------------------
# Generates a PDF report from the threat analysis HTML content. The report
# filename includes the threat level and timestamp for easy identification.
# Handles both Snort and ntopng-derived threat information in the content.
#
# Parameters:
#   $1 - threat_level: The highest threat level identified (HIGH/MEDIUM/LOW/N/A)
#   $2 - html_content: The analysis content in HTML format, including both
#        Snort and ntopng threat information
#
# Behavior:
#   - Creates timestamped PDF filename with sanitized threat level
#   - Generates temporary HTML file for wkhtmltopdf processing
#   - Converts HTML to PDF using wkhtmltopdf
#   - Validates PDF was created successfully
#   - Cleans up temporary files
#   - Logs success/failure
#
# Dependencies:
#   - wkhtmltopdf for PDF generation
#   - Temporary file creation
#
save_PDF_report() {
    local threat_level="$1"
    shift
    local html_content="$(decode "$1")"

    local cleaned_threat_level=$(echo "$threat_level" | sed 's/[\/\\]//g')
    local PDF_report_file="$REPORTS_DIR/report-$(date +%Y-%m-%d_%H-%M-%S)_$cleaned_threat_level.pdf"

    # Save HTML to a temporary file
    local temp_html=$(mktemp).html
    echo "$html_content" >"$temp_html"

    # Convert HTML to PDF
    wkhtmltopdf "$temp_html" "$PDF_report_file"

    # Clean up
    rm -f "$temp_html"

    # check if files exists and his non-null
    if [ ! -f "$PDF_report_file" ] || [ ! -s "$PDF_report_file" ]; then
        log "Failed to create PDF report or file is empty"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Function: create_webpage
# -----------------------------------------------------------------------------
# Generates the HTML interface displaying correlated Snort/ntopng analysis.
# Handles both updated content and cached displays when no new alerts exist.
#
# Parameters (base64 encoded):
#   $1 - updated: "true" if new analysis, "false" for cached display
#   $2 - expire_secs: Webpage expiration time in seconds
#   $3 - analysis: Formatted HTML analysis content
#   $4 - log_content: Recent Snort/ntopng log entries
#   $5 - api_response: Raw API response for debugging
#   $6 - error: Error message if applicable
#   $7 - snort_log_updated_time: Timestamp of last log modification
#
# Behavior:
#   - Decodes all input parameters
#   - Maintains last known good state for cached displays
#   - Formats timestamps for display (analysis time, log mod time, expiry)
#   - Generates complete HTML page with:
#     - Threat analysis section
#     - Recent log display (both Snort and ntopng)
#     - API response debug area
#     - Automatic refresh timing
#   - Applies consistent styling for threat level visualization
#
# Output:
#   - Creates/updates $WEB_DIR/index.html
#
create_webpage() {
    local updated="$1"                            # Whether the webpage is being updated
    local expire_secs="$(decode "$2")"            # Webpage expiration time in seconds
    local analysis="$(decode "$3")"               # Analysis content (base64 encoded)
    local log_content="$(decode "$4")"            # Log content (base64 encoded)
    local api_response="$(decode "$5")"           # API response content (base64 encoded)
    local error="$(decode "$6")"                  # Error message if applicable
    local snort_log_updated_time="$(decode "$7")" # Snort log last updated time

    if [ -z "$analysis" ]; then
        analysis="<p>No analysis available. $pfsense_availability_message</p>" # Default analysis content
    fi
    if [ -z "$log_content" ]; then
        log_content="No log content available. $pfsense_availability_message" # Default log content
    fi
    if [ -z "$api_response" ]; then
        api_response="No API response available." # Default API response content
    fi

    local update_time="n/a"

    # Check if the webpage is being updated
    if [ "$updated" = "false" ]; then
        if [ -n "$last_analysis" ]; then
            analysis="$last_analysis"
            log_content="$last_log_content"
            api_response="$last_response"
            if [ -z "$last_update_time" ]; then
                update_time="n/a"
            else
                update_time="$last_update_time"
            fi
        fi
    else
        last_analysis="$analysis"
        last_log_content="$log_content"
        last_response="$api_response"
        update_time=$(date '+%Y-%m-%d %H:%M:%S')
        last_update_time="$update_time"
    fi

    # HTML content
    local expire_time_str=$(date -d "$expire_secs seconds" -u '+%a, %d %b %Y %H:%M:%S GMT')
    local expire_time_str_short=$(date -d "$expire_secs seconds" '+%Y-%m-%d %H:%M:%S')
    log "Current webpage set to expire in $expire_secs seconds (by $expire_time_str_short)"

    # if snort_log_updated_time is 0 or before 2010, then display "n/a"
    # Check if variable is empty or not a number
    local snort_log_updated_time_str=""
    if [ -z "$snort_log_updated_time" ]; then
        snort_log_updated_time_str="n/a"
    elif [ "$snort_log_updated_time" -le 1262304000 ]; then
        snort_log_updated_time_str="n/a"
    else
        snort_log_updated_time_str=$(date -d "@$snort_log_updated_time" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "n/a")
    fi

    local update_status="<p class='timestamp'> Last analyzed: $update_time"
    if [ "$updated" = "false" ]; then
        if [ -z "$error" ]; then
            update_status+=" (No new alerts)"
        else
            update_status+=" (Last attempt: $error)"
        fi
    fi
    update_status+="<br>Snort logs last modified: $snort_log_updated_time_str $pfsense_availability_message<br>Webpage expires: $expire_time_str_short</p>"

    # Create the full HTML page
    cat <<EOF >"$WEB_DIR/index.html"
<html>
<head>
    <title>Alert Monitor (Snort & ntopng)</title>
    <meta http-equiv="Cache-Control" content="max-age=$expire_secs, must-revalidate">
    <meta http-equiv="Expires" content="$expire_time_str">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .high { color: red; font-weight: bold; }
        .medium { color: orange; }
        .low { color: green; }
        .timestamp { color: gray; font-size: 0.9em; }
        .log-container, .response-container {
            margin-top: 20px;
            border: 1px solid #ddd;
            padding: 10px;
            background-color: #f5f5f5;
        }
        .log-content, .response-content {
            height: 1200px;
            overflow-y: scroll;
            font-family: "Arial Narrow", Arial, sans-serif;
            font-size: 12pt;
            white-space: pre-wrap;
            padding: 5px;
            background-color: #fff;
            border: 1px solid #ccc;
        }
        .section-title {
            font-weight: bold;
            margin: 15px 0 5px 0;
        }
    </style>
</head>
<body>
    <h1>Alert Monitor (Snort & ntopng)</h1>
    $update_status
    
    <div class="section-title"></div>
    $analysis
    
    <br>
    <div class="section-title">Recent Snort and ntopng logs:</div>
    <div class="log-container">
        <div class="log-content">$log_content</div>
    </div>

</body>
</html>
EOF
}

# <div class="section-title">Last Successful API Response:</div>
# <div class="response-container">
#     <div class="response-content">$api_response</div>
# </div>

# -----------------------------------------------------------------------------
# Function: is_public_ip
# -----------------------------------------------------------------------------
# Determines if an IP address is public/routable, filtering out private,
# reserved, and internal addresses. Used to validate block list candidates
# from both Snort and ntopng sources.
#
# Parameters:
#   $1 - ip: IPv4 address to check
#
# Returns:
#   0 - IP is public/routable
#   1 - IP is private/reserved/invalid
#
# Filtered Ranges:
#   - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918)
#   - 169.254.0.0/16 (APIPA)
#   - 127.0.0.0/8 (loopback)
#   - 100.64.0.0/10 (Carrier-grade NAT)
#   - Invalid/malformed addresses
#
is_public_ip() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a octets <<<"$ip"
    for octet in "${octets[@]}"; do
        ((octet < 0 || octet > 255)) && return 1
    done
    [[ "${octets[0]}" -eq 10 ||
        ("${octets[0]}" -eq 172 && "${octets[1]}" -ge 16 && "${octets[1]}" -le 31) ||
        ("${octets[0]}" -eq 192 && "${octets[1]}" -eq 168) ||
        ("${octets[0]}" -eq 169 && "${octets[1]}" -eq 254) ||
        ("${octets[0]}" -eq 127) ||
        ("${octets[0]}" -eq 100 && "${octets[1]}" -ge 64 && "${octets[1]}" -le 127) ]] && return 1
    return 0
}

# Deletes block list files older than a specified number of days from the block list directory.
# Logs the cleanup operation and each deleted file.
#
# Globals:
#   BLOCK_LIST_DIR - Directory containing block list files.
#   DELETE_BLOCK_LISTS_AFTER - Number of days after which files should be deleted.
#   log - Function used for logging messages.
#
# Usage:
#   delete_old_block_lists
#
delete_old_block_lists() {
    local files_deleted="false"
    log "Performing cleanup of block list files older than $DELETE_BLOCK_LISTS_AFTER days"
    local deleted_any_file="false"
    while IFS= read -r deleted_file; do
        log "> deleted old block list file: $deleted_file"
        deleted_any_file="true"
    done < <(find "$BLOCK_LIST_DIR" -type f -mtime +"$DELETE_BLOCK_LISTS_AFTER" -delete -print)
    echo "$deleted_any_file"
}

# -----------------------------------------------------------------------------
# Function: consolidate_ips
# -----------------------------------------------------------------------------
# Processes IP addresses from generated block lists, applying validation
# and whitelist filtering. Handles IPs from both Snort alerts and ntopng
# traffic patterns. Creates a unified block list for firewall implementation.
#
# Steps:
#   1. Collects IPs from all block list files in $BLOCK_LIST_DIR
#   2. Validates each IP format and filters invalid addresses
#   3. Applies whitelist from $WHITELIST_FILE
#   4. Removes duplicates and sorts remaining IPs
#   5. Updates $CONSOLIDATED_FILE only if changes exist
#   6. Maintains audit logging of all actions
#
# Temporary Files:
#   - Uses mktemp for intermediate processing
#   - Ensures clean removal after processing
#
# Notes:
#   - Only processes valid, public IPv4 addresses
#   - Maintains idempotency - only updates consolidated file when needed
#   - Handles empty whitelist scenarios gracefully
#
consolidate_ips() {
    # Create empty whitelist if file doesn't exist
    [ -f "$WHITELIST_FILE" ] || touch "$WHITELIST_FILE"

    # create fake block list file from blacklist file to ensure includion of these IPs in the consolidation
    cat "$BLACKLIST_FILE" >"$BLOCK_LIST_DIR/block-list-1900-01-01_00-00-00.txt"

    # Temporary files for processing
    TEMP_ALL_IPS=$(mktemp)
    TEMP_VALID_IPS=$(mktemp)
    TEMP_FILTERED_IPS=$(mktemp)

    # Stage 1: Extract all IPs from all block list files
    find "$BLOCK_LIST_DIR" -type f -exec grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' {} + | sed 's/.*://' >"$TEMP_ALL_IPS"

    # Stage 2: Filter only valid IPs
    while read -r ip; do
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            IFS='.' read -r -a octets <<<"$ip"
            valid=true
            for octet in "${octets[@]}"; do
                if ((octet < 0 || octet > 255)); then
                    valid=false
                    break
                fi
            done
            $valid && echo "$ip"
        fi
    done <"$TEMP_ALL_IPS" >"$TEMP_VALID_IPS"

    # Stage 3: Remove whitelisted IPs (only if whitelist isn't empty)
    if [ -s "$WHITELIST_FILE" ]; then
        grep -vxFf <(grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$WHITELIST_FILE") "$TEMP_VALID_IPS" >"$TEMP_FILTERED_IPS"
    else
        cp "$TEMP_VALID_IPS" "$TEMP_FILTERED_IPS"
    fi

    # Stage 4: Sort and deduplicate (only if we have results)
    if [ -s "$TEMP_FILTERED_IPS" ]; then
        sort -u -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n "$TEMP_FILTERED_IPS" >"$CONSOLIDATED_FILE.tmp"
        # Only update if the new content differs
        if ! cmp -s "$CONSOLIDATED_FILE.tmp" "$CONSOLIDATED_FILE"; then
            cat "$CONSOLIDATED_FILE.tmp" >"$CONSOLIDATED_FILE"
            rm -f "$CONSOLIDATED_FILE.tmp"
            log "Consolidated block list updated. Requesting pfSense block-list reload."
            sleep 1
            $SCRIPT_DIR/force-pfsense-ntopng-update.sh &
        else
            rm "$CONSOLIDATED_FILE.tmp"
        fi
    elif [ -f "$CONSOLIDATED_FILE" ]; then
        # Remove old file if we have no IPs to block
        rm "$CONSOLIDATED_FILE"
        log "No IPs to block after filtering"
    fi

    # Cleanup temp files
    rm -f "$TEMP_ALL_IPS" "$TEMP_VALID_IPS" "$TEMP_FILTERED_IPS"
}

is_blocked() {
    local ip="$1"
    if [ -z "$ip" ]; then
        return 1 # Empty IP is not blocked
    fi
    if grep -q -F "$ip" "$CONSOLIDATED_FILE"; then
        return 0 # IP is blocked
    else
        return 1 # IP is not blocked
    fi
}

is_whitelisted() {
    local ip="$1"
    if [ -z "$ip" ]; then
        return 1 # Empty IP is not whitelisted
    fi
    if grep -q -F "$ip" "$WHITELIST_FILE"; then
        return 0 # IP is whitelisted
    else
        return 1 # IP is not whitelisted
    fi
}

flag_unblocked_IPs() {
    local html="$(decode "$1")"

    # Regex to match IP addresses (IPv4)
    local ip_regex='([0-9]{1,3}\.){3}[0-9]{1,3}'

    # Find all unique IP addresses in the HTML
    local ips
    ips=$(echo "$html" | grep -E -o "$ip_regex" | sort -u)

    # Process each IP
    while read -r ip; do
        if is_public_ip "$ip"; then
            if is_whitelisted "$ip"; then
                # IP is whitelisted - mark halo emoji (😇)
                html=$(echo "$html" | sed "s/$ip/\&#x1F607; $ip/g")
            elif is_blocked "$ip"; then
                # IP is blocked - add no entry emoji (🚫)
                html=$(echo "$html" | sed "s/$ip/\&#x1F6AB; $ip/g")
            else
                # IP is public but not blocked and not whitelisted - add police light emoji (🚨)
                html=$(echo "$html" | sed "s/$ip/\&#x1F6A8; $ip/g")
            fi
        fi
    done <<<"$ips"
    # Return processed HTML
    echo "$(encode "$html")"
}

# Background monitoring function
start_monitor() {
    log "Starting block list monitor"

    # Use inotifywait to monitor only for new files
    inotifywait -m -q -e create -e moved_to --format "%w%f" "$BLOCK_LIST_DIR" |
        while read -r file; do
            # Only process regular files (ignore directories)
            if [ -f "$file" ]; then
                log "Detected new file: $file"

                # Cleanup old files before processing new one
                find "$BLOCK_LIST_DIR" -type f -mtime +"$DELETE_BLOCK_LISTS_AFTER" -delete -print | while read -r deleted_file; do
                    log "Deleted old file: $deleted_file"
                done
                if is_auto_consolidation_enabled; then
                    log "Consolidating IPs from new file: $file"
                    consolidate_ips
                else
                    log "Skipping auto consolidation due to skip_auto_consolidation flag"
                fi
            fi
        done
}

# -----------------------------------------------------------------------------
# Function: cleanup
# -----------------------------------------------------------------------------
# This function is responsible for gracefully stopping all background processes started by the Snort Monitor service.
# It attempts to terminate each process using their respective process IDs (PIDs), first with a standard kill signal,
# and then with a forceful kill (-9) if the process does not terminate. The function logs the status of each process
# termination and confirms whether all processes have been stopped successfully before exiting the script.
#
# Processes handled:
# - MONITOR_PID: Main monitor process
# - WHITELIST_UPDATER_1_PID: Whitelist updater process #1
# - WHITELIST_UPDATER_2_PID: Whitelist updater process #2
# - BLOCK_LIST_SERVER_PID: Block list server process
# - WEB_SERVER_PID: Web server process
#
# Logs are generated for each step, and the function ensures a clean shutdown of the service.
#
cleanup() {
    kill "$MONITOR_PID" 2>/dev/null
    kill "$WHITELIST_UPDATER_1_PID" 2>/dev/null
    kill "$WHITELIST_UPDATER_2_PID" 2>/dev/null
    kill "$BLOCK_LIST_SERVER_PID" 2>/dev/null
    kill "$WEB_SERVER_PID" 2>/dev/null
    if [ -n "$PFSENSE_THERMALS_MONITOR_PID" ]; then
        kill "$PFSENSE_THERMALS_MONITOR_PID" 2>/dev/null
    fi
    if [ -n "$PFSENSE_RESTART_PID" ]; then
        kill "$PFSENSE_RESTART_PID" 2>/dev/null
    fi
    sleep 2

    rm -f "$skip_auto_consolidation_flag_file" >/dev/null 2>&1

    # Check if the processes are still running
    if ps -p "$MONITOR_PID" >/dev/null; then
        log "Monitor process is still running, stopping it..."
        kill -9 "$MONITOR_PID"
    fi
    if ps -p "$WHITELIST_UPDATER_1_PID" >/dev/null; then
        log "Whitelist updater process #1 is still running, stopping it..."
        kill -9 "$WHITELIST_UPDATER_1_PID"
    fi
    if ps -p "$WHITELIST_UPDATER_2_PID" >/dev/null; then
        log "Whitelist updater process #2 is still running, stopping it..."
        kill -9 "$WHITELIST_UPDATER_2_PID"
    fi
    if ps -p "$BLOCK_LIST_SERVER_PID" >/dev/null; then
        log "Block list server process is still running, stopping it..."
        kill -9 "$BLOCK_LIST_SERVER_PID"
    fi
    if ps -p "$WEB_SERVER_PID" >/dev/null; then
        log "Web server process is still running, stopping it..."
        kill -9 "$WEB_SERVER_PID"
    fi
    if [ -n "$PFSENSE_THERMALS_MONITOR_PID" ]; then
        if ps -p "$PFSENSE_THERMALS_MONITOR_PID" >/dev/null; then
            log "pfSense thermal monitor is still running, stopping it..."
            kill -9 "$PFSENSE_THERMALS_MONITOR_PID"
        fi
    fi
    if [ -n "$PFSENSE_RESTART_PID" ]; then
        if ps -p "$PFSENSE_RESTART_PID" >/dev/null; then
            log "pfSense restart daemon is still running, stopping it..."
            kill -9 "$PFSENSE_RESTART_PID"
        fi
    fi
    sleep 2
    if ! ps -p "$MONITOR_PID" >/dev/null &&
        ! ps -p "$WHITELIST_UPDATER_1_PID" >/dev/null &&
        ! ps -p "$WHITELIST_UPDATER_2_PID" >/dev/null &&
        ! ps -p "$BLOCK_LIST_SERVER_PID" >/dev/null &&
        ! ps -p "$WEB_SERVER_PID" >/dev/null; then
        log "All background processes stopped successfully"
    else
        log "Some background processes failed to stop"
    fi
    log "**************** Exiting Snort Monitor Service ****************"
    exit 0
}

# -----------------------------------------------------------------------------
# Function: update_analysis
# -----------------------------------------------------------------------------
# Core function that performs periodic analysis of Snort and ntopng logs.
# Correlates data from both sources, generates threat assessments via API,
# and triggers follow-up actions including web updates and block list
# generation.
#
# Parameters:
#   $1 - expires_in: Encoded webpage expiration time in seconds
#
# Workflow:
#   1. Checks log file timestamps for new activity
#   2. Collects recent entries from both Snort and ntopng logs
#   3. Submits correlated data to analysis API
#   4. Processes API response to extract threat information
#   5. Updates web interface with new analysis
#   6. Generates PDF report for the analysis session
#   7. Optionally creates block lists based on threat level
#   8. Maintains timing markers to prevent duplicate processing
#
# API Interaction:
#   - Uses $ANALYSIS_PROMPT_TEXT for primary analysis
#   - Uses $BLOCKLIST_PROMPT_TEXT for block list generation
#   - Handles API errors gracefully with retry logic
#
# Concurrency:
#   - PDF generation and block list creation run in background
#   - Web interface updates are atomic
#
# Outputs:
#   - Updates web interface
#   - Generates PDF reports
#   - May create new block list files
#
update_analysis() {
    local expires_in="$(decode "$1")" # Web page expiration time in seconds

    local last_check=$(cat "$TIMESTAMP_FILE" 2>/dev/null || echo 0)               # Last time logs were checked
    local snort_log_updated_time=$(stat -c %Y "$SNORT_LOG" 2>/dev/null || echo 0) # Current modification time of the log file

    local analysis=""
    local cleaned_analysis=""
    local enc_cleaned_analysis=""
    local enc_flagged_analysis=""
    local cleaned_response=""
    local response_no_extra_spaces=""
    local error=""
    local json_last_analysis=""
    local json_log_content=""
    local log_lines=""
    local log_lines_snort=""
    local log_lines_ntopng=""
    local enc_log_lines=""
    local enc_flagged_log_lines=""
    local request_json=""
    local response=""
    local time_now=$(date '+%Y-%m-%d %H:%M:%S')
    local normalized_html=""
    local highest_threat_level="N/A"
    local blocked_ips=$(paste -sd, "$CONSOLIDATED_FILE")
    local ntopng_logs_lines_to_show=0
    local should_update="true"

    if [ "$snort_log_updated_time" -le "$last_check" ]; then
        log "No updates to Snort log since last check"
        should_update="false"
    else
        # Get snort log content
        log_lines_snort=$(tail -n "$LOG_LINES_TO_SHOW" "$SNORT_LOG")

        # resolve ntopng log lines with DNS addresses to IPs (not necessary if ntopng configured to not lookup numerical IPs)

        if [ "$INCLUDE_NTOPNG_LOGS" = true ]; then
            local temp_ntopng_in_file=$(mktemp)
            local temp_ntopng_out_file=$(mktemp)
            touch "$temp_ntopng_out_file"
            # get 2x more lines from ntopng log to ensure we have enough data
            ntopng_logs_lines_to_show=$((LOG_LINES_TO_SHOW * 2))
            tail -n "$ntopng_logs_lines_to_show" "$NTOPNG_LOG" >"$temp_ntopng_in_file"
            $SCRIPT_DIR/resolve-ntopng-log.sh "$temp_ntopng_in_file" "$temp_ntopng_out_file"
            log_lines_ntopng=$(cat "$temp_ntopng_out_file")
            rm -f "$temp_ntopng_in_file" "$temp_ntopng_out_file"
        else
            log_lines_ntopng="ntopng logs not available."
        fi

        log_lines="$(
            printf %b "---------------------------------------------------\n\t START OF SNORT LOGS \n---------------------------------------------------\n"
            echo "$log_lines_snort"
            printf %b "---------------------------------------------------\n\t END OF SNORT LOGS \n---------------------------------------------------\n"
            printf %b "---------------------------------------------------\n\t START OF NTOPNG LOGS \n---------------------------------------------------\n"
            echo "$log_lines_ntopng"
            printf %b "---------------------------------------------------\n\t END OF NTOPNG LOGS \n---------------------------------------------------\n"
        )"
        json_log_content=$(echo $log_lines | escape_json | tr -s ' ')
        json_last_analysis=""
        last_analysis=$(echo "$last_analysis" | tr -d '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        if [ -n "$last_analysis" ]; then
            json_last_analysis="--------------------------------------------------- LAST ANALYSIS: ---------------------------------------------------"
            json_last_analysis+="This is the last analysis you provided.  Please review it and use it as a guide for identifying patterns and making prioritizations and formating consistent over time: "
            json_last_analysis+=$(echo "$last_analysis" | escape_json)
        fi

        if [ -n "$blocked_ips" ]; then
            blocked_ips="--------------------------------------------------- ALREADY BLOCKED IPs: --------------------------------------------------- $blocked_ips"
        fi
        export TOKEN_LIMIT # make max tokens setting available to jq
        request_json=$(jq -n \
            --arg model "$MODEL" \
            --arg system_content "$ANALYSIS_PROMPT_TEXT" \
            --arg user_content "$json_log_content.  
            $json_last_analysis 
            $blocked_ips" \
            '{
            model: $model,
            messages: [
                {
                    role: "system",
                    content: $system_content
                },
                {
                    role: "user",
                    content: $user_content
                }
            ],
            temperature: 0.7,
            max_tokens: env.TOKEN_LIMIT | tonumber
        }')
# env.TOKEN_LIMIT | tonumber
        printf "Last request JSON for Analysis:\n%s\n" "$request_json" >"$SCRIPT_DIR/last_analysis_request.log"

        # Call the API with a request for an analysis
        response=$(curl -s -X POST "$API_ENDPOINT" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $API_KEY" \
            -d "$request_json")

        response_no_extra_spaces=$(echo "$response" | tr -s ' ')
        printf "Last response JSON for Analysis:\n%s\n" "$response_no_extra_spaces" >"$SCRIPT_DIR/last_analysis_response.log"

        # Handle response
        if [ $? -eq 0 ]; then
            if [[ "$response" == *"error"* ]]; then
                log "Analysis request API ERROR: $(echo "$response" | jq -r '.error.message')"
                error="API Error"
                should_update="false"
            else
                analysis=$(echo "$response" | jq -r '.choices[0].message.content')
                cleaned_analysis=$(remove_backticks "$analysis" | sed 's/^html//')
                log "Cleaned analysis: $cleaned_analysis"
                cleaned_response=$(echo "$response" | sed 's/  \+/ /g' | tr '\n' ' ' | escape_html)
                log "Analysis request: API call SUCCEEDED, received valid response $cleaned_response."
            fi
        else
            log "Analysis request: FAILED to connect to API. Exit code: $?"
            error="API Connection Failed [$?]"
            should_update="false"
        fi

    fi

    # Extract the threat level
    if [ "$should_update" = "true" ]; then
        normalized_html=$(echo "$cleaned_analysis" | tr -d '\n' | sed 's/>[[:space:]]*</></g')
        highest_threat_level=$(echo "$normalized_html" | grep -o -i '<h2[^>]*>HIGHEST THREAT LEVEL REACHED[^<]*</h2>[[:space:]]*<p[^>]*>[[:space:]]*[^<]*[[:space:]]*</p>' | sed -E 's/.*<p[^>]*>[[:space:]]*([^<[:space:]]+)[[:space:]]*<\/p>.*/\1/')
        highest_threat_level=$(echo "$highest_threat_level" | tr '[:lower:]' '[:upper:]' | xargs)

        highest_threat_level=${highest_threat_level^^}
        case "$highest_threat_level" in
        "HIGH" | "MEDIUM" | "LOW")
            # Valid value, keep it
            ;;
        *)
            highest_threat_level="N/A"
            ;;
        esac

        log "Threat level detected: $highest_threat_level"
    fi

    # Update the last check time
    date +%s >"$TIMESTAMP_FILE"

    # Create the webpage
    # create_webpage "$should_update" "$(encode $expires_in)" "$(encode $cleaned_analysis)" "$(encode $escaped_snort_log_lines)" "$(encode $cleaned_response)" "$(encode $error)" "$(encode $snort_log_updated_time)"

    if [ "$should_update" = "true" ]; then
        # Save the report as a PDF

        # Create a list of IPs to block
        # if [[ "$highest_threat_level" == "HIGH" ]] || [[ "$initial_consolidation" == "true" ]]; then
        export TOKEN_LIMIT # make max tokens setting available to jq
        request_json=$(
            jq -n \
                --arg model "$MODEL" \
                --arg system_content "$BLOCKLIST_PROMPT_TEXT" \
                --arg user_content "SUPPORTING MATERIALS:
Here is a recent threat analysis: $(echo $cleaned_analysis | tr -s ' ') \n
Here are some recent Snort and ntopng logs. Please extract and provide in your response all external IPs that are listed in lines containing [Blacklisted Client Contact]: $json_log_content \n
The following IPs have already been blocked so you do not need to include them in your response: $blocked_ips" \
                '{
                 model: $model,
                 messages: [
                   {role: "system", content: $system_content},
                   {role: "user",   content: $user_content}
                 ],
                 temperature: 0.1,
                 max_tokens: env.TOKEN_LIMIT | tonumber
               }'
        )

        printf "Last request JSON for blocked IPs:\n%s\n" "$request_json" >"$SCRIPT_DIR/last_IPs_to_block_request.log"

        response=$(curl -s -X POST "$API_ENDPOINT" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $API_KEY" \
            -d "$request_json")

        response_no_extra_spaces=$(echo "$response" | tr -s ' ')
        printf "Last response JSON for blocked IPs:\n%s\n" "$response_no_extra_spaces" >"$SCRIPT_DIR/last_IPs_to_block_response.log"

        if [ $? -eq 0 ]; then
            if [[ "$response" == *"error"* ]]; then
                log "Block List request API Error: $(echo "$response" | jq -r '.error.message')"
            else
                local block_list=$(echo "$response" | jq -r '.choices[0].message.content' | sed 's/  \+/ /g')

                if [ -n "$block_list" ]; then

                    local ip_trimmed=""
                    local cleaned_block_list=$(echo "$block_list" | while read -r ip; do
                        ip_trimmed=$(echo "$ip" | xargs)
                        [[ -z "$ip_trimmed" ]] && continue
                        is_public_ip "$ip_trimmed" && echo "$ip_trimmed"
                    done)

                    if [ -n "$cleaned_block_list" ]; then
                        local block_list_file="$BLOCK_LIST_DIR/block-list-$(date +%Y-%m-%d_%H-%M-%S).txt"
                        disable_auto_consolidation
                        echo "$cleaned_block_list" >"$block_list_file"
                        # De-duplicate the block list file
                        sort "$block_list_file" | uniq >"${block_list_file}.tmp"
                        cat "${block_list_file}.tmp" >"$block_list_file"
                        cleaned_block_list=$(cat "$block_list_file")
                        log "Block list:"
                        log "$cleaned_block_list"
                        log "Block list saved to file $block_list_file"
                        sleep 0.5
                        consolidate_ips
                        sleep 1
                        enable_auto_consolidation
                    else
                        log "Block List request: No valid IPs to block found in API response."
                    fi

                fi
            fi
        else
            log "Block List request: Failed to connect to API. Exit code: $?"
        fi

        # fi
    fi

    if [ -n "$cleaned_analysis" ]; then
        enc_cleaned_analysis="$(encode "$cleaned_analysis")"
        enc_flagged_analysis="$(flag_unblocked_IPs "$enc_cleaned_analysis")"
        # cleaned_analysis=$(decode "$cleaned_analysis")
        enc_log_lines="$(encode "$log_lines")"
        enc_flagged_log_lines="$(flag_unblocked_IPs "$enc_log_lines")"

        save_PDF_report "$highest_threat_level" "$enc_flagged_analysis" &
        create_webpage "$should_update" "$(encode $expires_in)" "$enc_flagged_analysis" "$enc_flagged_log_lines" "$(encode $cleaned_response)" "$(encode $error)" "$(encode $snort_log_updated_time)"
    fi
}

# -----------------------------------------------------------------------------
# Function: calculate_perturbed_interval
# -----------------------------------------------------------------------------
# Computes randomized intervals for periodic analysis to prevent predictable
# patterns in API calls and log processing. Applies jitter to base interval
# while ensuring reasonable bounds.
#
# Algorithm:
#   - Generates random value in [INTERVAL_PERTURBATION_MIN, INTERVAL_PERTURBATION_MAX]
#   - Multiplies base UPDATE_INTERVAL by this factor
#   - Ensures result is positive integer
#   - Provides sufficient variability while maintaining overall periodicity
#
# Output:
#   - Prints calculated interval in seconds to stdout
#
# Notes:
#   - Helps avoid pattern detection in API usage
#   - Maintains overall average near UPDATE_INTERVAL
#   - Uses awk for precise floating point calculations
#
calculate_perturbed_interval() {
    # Generate random perturbation factor between min and max
    local random_perturbation=$(awk -v min=$INTERVAL_PERTURBATION_MIN -v max=$INTERVAL_PERTURBATION_MAX \
        'BEGIN { srand(); print min + rand() * (max - min) }')

    # Calculate perturbed refresh interval (rounded to nearest integer)
    local perturbed_refresh=$(awk -v base=$UPDATE_INTERVAL -v pert=$random_perturbation \
        'BEGIN { printf "%.0f", base * pert }')

    # Ensure we don't get values <= 0
    ((perturbed_refresh = perturbed_refresh > 0 ? perturbed_refresh : 1))

    echo $perturbed_refresh
}

# -----------------------------------------------------------------------------
# Function: update_whitelist_runner
# -----------------------------------------------------------------------------
# Description:
#   Runs a background loop that automatically updates the whitelist at a
#   specified hour each day, as defined by the AUTO_UPDATE_HOUR variable.
#   The update is performed only if AUTO_UPDATE_WHITELIST_BOOL is set to true.
#   The function calculates the time until the next scheduled update, sleeps
#   until that time, then executes the whitelist update script
#   (extract-good-ips-from-block-list.sh). The output of the script is logged
#   and appended to a log file (whitelist_update.log).
#
# Parameters:
#   run_hour                   - Target hour for daily update (e.g., "03:00").
#
# Globals:
#   AUTO_UPDATE_WHITELIST_BOOL - Boolean flag to enable/disable auto-update.
#   SCRIPT_DIR                 - Directory containing the update script.
#
# Dependencies:
#   - extract-good-ips-from-block-list.sh: Script to perform the actual update.
#   - log: Function to log messages.
#
# Usage:
#   update_whitelist_runner
#
update_whitelist_runner() {
    local run_hour="$1"
    if [ -n "$run_hour" ]; then

        local files_deleted=false

        # Background loop running task at run_hour daily
        if [ "$AUTO_UPDATE_WHITELIST_BOOL" = true ]; then
            local script_output=""
            while true; do
                # Calculate now and next AUTO_UPDATE_HOUR
                now=$(date +%s)
                target=$(date -d "today $run_hour" +%s)
                if ((now >= target)); then
                    target=$(date -d "tomorrow $run_hour" +%s)
                fi
                sleep $((target - now))

                log "Auto-updating whitelist now..."

                # Run the whitelist update script
                echo "Running whitelist update script: $SCRIPT_DIR/extract-good-ips-from-block-list.sh"
                script_output="$($SCRIPT_DIR/extract-good-ips-from-block-list.sh)"
                log "Whitelist update script output: $script_output"
                echo "$script_output" >"$SCRIPT_DIR/whitelist_update.log"
                sudo chown "$LOCAL_USER_AND_GROUP" "$SCRIPT_DIR/whitelist_update.log"
                sudo chmod 666 "$SCRIPT_DIR/whitelist_update.log"

                # Delete old block list files
                files_deleted=$(delete_old_block_lists)
                if [ "$files_deleted" = true ]; then
                    disable_auto_consolidation
                    consolidate_ips
                    sleep 1
                    enable_auto_consolidation
                fi

            done

        fi
    fi
}

# restart_pfsense_periodically
# Periodically restarts pfSense at a specified hour each day.
#
# Arguments:
#   $1 - The hour (in HH:MM format) at which to run the pfSense reboot script daily.
#
# Behavior:
#   - Calculates the time until the next scheduled run based on the provided hour.
#   - Sleeps until the scheduled time.
#   - Executes the pfSense reboot script located at $SCRIPT_DIR/force-pfsense-to-reboot.sh.
#   - Logs the output of the reboot script.
#   - Repeats this process indefinitely.
restart_pfsense_periodically() {
    local run_hour="$1"

    local script_output=""
    while true; do
        # Calculate now and next AUTO_UPDATE_HOUR
        now=$(date +%s)
        target=$(date -d "today $run_hour" +%s)
        if ((now >= target)); then
            target=$(date -d "tomorrow $run_hour" +%s)
        fi
        sleep $((target - now))

        echo "Running pfSense reboot script: $SCRIPT_DIR/force-pfsense-to-reboot.sh"
        script_output="$($SCRIPT_DIR/force-pfsense-to-reboot.sh)"
        log "$script_output"
    done
}

log_pfsense_thermals() {
    local thermal_status=""
    local load_status=""
    while true; do
        # Get the thermal and load statuses from pfSense
        read -r thermal_status load_status < <("$SCRIPT_DIR/get-pfsense-thermal.sh" -l)

        # check if thermal_status is an integer
        if ! [[ "$thermal_status" =~ ^-?[0-9]+$ ]]; then
            log "Error: pfSense Thermal status is not a valid integer: $thermal_status"
        else
            if ! [[ "$load_status" =~ ^-?[0-9]+$ ]]; then
                log "Error: pfSense CPU load status is not a valid integer: $load_status"
            else
                # Log the thermal status with timestamp
                log "pfSense thermal status: $thermal_status"
                log "pfSense CPU load status: $load_status"
                touch "$PFSENSE_THERMALS_LOG"
                echo "$(date '+%Y-%m-%d %H:%M:%S') - $thermal_status, $load_status" >>"$PFSENSE_THERMALS_LOG"
            fi
        fi
        # Sleep for a defined interval before checking again
        sleep "$PFSENSE_THERMALS_INTERVAL"
    done
}

# -----------------------------------------------------------------------------
# MAINLINE
# -----------------------------------------------------------------------------
# This mainline starts and manages the Snort Monitor Service.
#
# Main functionalities:
# - Logs the startup of the Snort Monitor Service and its components.
# - Starts an alert web server and stores its PID.
# - Creates an initial webpage indicating that log analysis is pending.
# - Performs initial block list consolidation.
# - Starts a background process to periodically update the whitelist.
# - Starts a background log monitor process.
# - Starts a web server to share the block list and stores its PID.
# - Sets up a trap to ensure all background processes are terminated when the script exits.
# - Logs the PIDs and file paths of all major components for monitoring and debugging.
# - Enters a main loop that:
#     - Sets initial expiration and interval values for the first analysis.
#     - For subsequent iterations, calculates a perturbed interval and expiration time.
#     - Updates the analysis webpage with the new expiration time.
#     - Sleeps for the calculated interval before repeating.
#
# Variables:
# - WEB_PORT: Port for the alert web server.
# - BLOCK_LIST_WEB_PORT: Port for the block list web server.
# - WEBPAGE_EXPIRATION_GRACE: Grace period for webpage expiration.
# - WHITELIST_FILE: Path to the whitelist file.
# - CONSOLIDATED_FILE: Path to the consolidated block-list file.
#
# Background processes:
# - Alert web server
# - Whitelist updater
# - Log monitor
# - Block list web server
#
# Cleanup:
# - All background processes are terminated on script exit via the 'cleanup' function.
#
# Dependencies:
# - Functions: log, start_web_server, create_webpage, encode, consolidate_ips, update_whitelist_runner, start_monitor,
#   share_block_list_via_HTTP, calculate_perturbed_interval, update_analysis, cleanup
#
log "**************** Starting Snort Monitor Service ****************"
log "Starting alert web server on port $WEB_PORT"
start_web_server &
ALERT_WEB_SERVER_PID=$!
sleep 2

if ping -c 1 "$PFSENSE_FW_IP" >/dev/null 2>&1; then
    pfsense_availability_message=""
else
    pfsense_availability_message="pfSense firewall is not available."
fi

create_webpage "false" "$(encode $WEBPAGE_EXPIRATION_GRACE)" "$(encode "Waiting for the first log analysis... $pfsense_availability_message")" "$(encode "Waiting for the first log analysis... $pfsense_availability_message")" "" "" ""

# Initial block list consolidation

first_time=true
delete_old_block_lists
consolidate_ips

# Start the whitelist updaters in the background
update_whitelist_runner $AUTO_UPDATE_HOUR_1 &
WHITELIST_UPDATER_1_PID=$!
update_whitelist_runner $AUTO_UPDATE_HOUR_2 &
WHITELIST_UPDATER_2_PID=$!

# Start the log monitor in background
start_monitor >/dev/null 2>&1 &
MONITOR_PID=$!

log "Starting block list web server on port $BLOCK_LIST_WEB_PORT"
share_block_list_via_HTTP &
BLOCK_LIST_WEB_SERVER_PID=$!

# Start the pfSense thermal status monitor if enabled
if [ "$MONITOR_PFSENSE_THERMALS" = true ]; then
    log "Starting pfSense thermal status monitor"
    log_pfsense_thermals &
    PFSENSE_THERMALS_MONITOR_PID=$!
else
    log "pfSense thermal status monitoring is disabled."
    PFSENSE_THERMALS_MONITOR_PID=""
fi

# Start the periodic pfSense restart daemon if configured
if [ "$PFSENSE_RESTART" = true ]; then
    restart_pfsense_periodically $PFSENSE_RESTART_HOUR &
    PFSENSE_RESTART_PID=$!
    log "pfSense periodic restart daemon PID: $PFSENSE_RESTART_PID"
else
    log "pfSense will not be restarted periodically."
    PFSENSE_RESTART_PID=""
fi

# Trap script exit to kill all background processes
trap cleanup EXIT

log "Alert Web server started with PID: $ALERT_WEB_SERVER_PID"
log "Block list monitor running (PID: $MONITOR_PID)"
if [ "$AUTO_UPDATE_WHITELIST_BOOL" = true ]; then
    if [ -n "$AUTO_UPDATE_HOUR_1" ]; then
        log "Whitelist updater #1 ($AUTO_UPDATE_HOUR_1) running (PID: $WHITELIST_UPDATER_1_PID)"
    else
        log "Whitelist updater #1 innactive."
    fi
    if [ -n "$AUTO_UPDATE_HOUR_2" ]; then
        log "Whitelist updater #2 ($AUTO_UPDATE_HOUR_2) running (PID: $WHITELIST_UPDATER_2_PID)"
    else
        log "Whitelist updater #2 innactive."
    fi
else
    log "Whitelist updaters are disabled."
fi
log "Block list web server running (PID: $BLOCK_LIST_WEB_SERVER_PID)"
log "Whitelist file: $WHITELIST_FILE"
log "Block-list file: $CONSOLIDATED_FILE"

enable_auto_consolidation

# Main loop
while true; do
    if $first_time; then
        first_time=false
        expiration_time=40 # Initial expiration time for the first analysis
        perturbed_interval=15
    else
        perturbed_interval=$(calculate_perturbed_interval)
        expiration_time=$(printf "%.0f" "$((perturbed_interval + WEBPAGE_EXPIRATION_GRACE))")
    fi

    # ping PFSENSE_FW_IP to check that it is available
    if ping -c 1 "$PFSENSE_FW_IP" >/dev/null 2>&1; then
        log "pfSense firewall is available, proceeding with analysis update."
        pfsense_availability_message=""
        update_analysis "$(encode $expiration_time)"
    else
        log "pfSense firewall is not available, skipping analysis update."
        pfsense_availability_message="pfSense firewall is not available."
    fi

    sleep "$perturbed_interval"
done
