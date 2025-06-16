#!/bin/bash
# -----------------------------------------------------------------------------
# snort-monitor.sh
#
# Overview:
#   This script provides a comprehensive monitoring and analysis solution for
#   Snort IDS and ntopng network traffic logs. It performs periodic analysis
#   of both log sources, generates prioritized threat summaries using the
#   OpenAI API, and serves the results as a dynamic web page. The integrated
#   solution provides enhanced network visibility by correlating intrusion
#   detection alerts with traffic flow patterns.
#
# Features:
#   - Periodic analysis of Snort IDS alerts and ntopng traffic logs with
#     configurable intervals and randomized timing to avoid patterns
#   - Integration with OpenAI API for advanced threat correlation and analysis
#   - Dynamic HTML web page generation with threat summaries and log content
#   - Simple Python-based HTTP server with cache control for serving results
#   - Automated block list generation and consolidation with whitelist filtering
#   - PDF report generation for each analysis session
#   - Graceful error handling and automatic retries for API/server failures
#   - Background monitoring of block list directory for real-time updates
#
# Configuration:
#   - SNORT_LOG: Path to Snort alert log file (from snort-monitor.conf)
#   - NTOPNG_LOG: Path to ntopng log file (from snort-monitor.conf)
#   - API_ENDPOINT/API_KEY/MODEL: OpenAI API configuration
#   - WEB_DIR: Directory for web interface files
#   - TIMESTAMP_FILE: Tracks last analysis time
#   - LOG_FILE: Script activity log location
#   - BLOCK_LIST_DIR: Storage for generated block lists
#   - CONSOLIDATED_FILE_SHARE: Shared location for final block list
#   - WHITELIST_FILE: IP addresses to exclude from blocking
#   - REPORTS_DIR: Storage for generated PDF reports
#   - UPDATE_INTERVAL: Base analysis interval (seconds)
#   - INTERVAL_PERTURBATION_MIN/MAX: Range for randomizing intervals
#   - WEBPAGE_EXPIRATION_GRACE: Buffer time for analysis completion
#   - WEB_PORT: Web interface port
#   - LOG_LINES_TO_SHOW: Number of log lines to process/display
#   - BLOCK_LIST_WEB_PORT: Block list sharing port
#   - DELETE_BLOCK_LISTS_AFTER: Retention period for block lists (days)
#
# Dependencies:
#   - Bash shell
#   - Python 3 (for HTTP servers)
#   - jq (JSON processing)
#   - curl (API requests)
#   - wkhtmltopdf (PDF report generation)
#   - inotify-tools (directory monitoring)
#
# Main Functions:
#   - log: Timestamped logging utility
#   - escape_json/html: Data sanitization functions
#   - encode/decode: Base64 parameter handling
#   - remove_backticks: Text formatting cleanup
#   - start_web_server: Main analysis web interface
#   - share_block_list_via_HTTP: Block list sharing service
#   - save_PDF_report: Report generation
#   - create_webpage: HTML content generation
#   - is_public_ip: IP address classification
#   - consolidate_ips: Block list processing
#   - start_monitor: Directory watcher for block lists
#   - cleanup: Exit handler
#   - update_analysis: Core analysis workflow
#   - calculate_perturbed_interval: Randomized timing
#
# Usage:
#   1. Configure snort-monitor.conf with paths and API credentials
#   2. Run script to start monitoring and web interface
#   3. Access analysis at http://<server>:<WEB_PORT>
#   4. Access block list at http://<server>:<BLOCK_LIST_WEB_PORT>
#
# Notes:
#   - Designed for continuous operation with resilience features
#   - All generated files are managed in configured directories
#   - Web interface and block lists auto-refresh
#   - Correlates Snort alerts with ntopng traffic patterns
# -----------------------------------------------------------------------------
#
# Shellcheck directives
# shellcheck disable=SC2155
# shellcheck disable=SC2181
# shellcheck disable=SC1091
# shellcheck disable=SC2086
# shellcheck disable=SC2001

# Configuration variables THAT SHOULD BE OVERRIDDEN IN SNORT-MONITOR.CONF
SNORT_LOG="<provide SNORT_LOG in .conf file>"   # Path to the snort log file (sourced from snort-monitor.conf
NTOPNG_LOG="<provide NTOPNG_LOG in .conf file>" # Path to the ntopng log file (sourced from snort-monitor.conf)
API_ENDPOINT=""                                 # OpenAI API endpoint (sourced from snort-monitor.conf)
API_KEY=""                                      # OpenAI API key (sourced from snort-monitor.conf)
MODEL=""                                        # OpenAI model to use (sourced from snort-monitor.conf)

# Default configuration variables THAT SHOULD BE OVERRIDDEN IN SNORT-MONITOR.CONF
UPDATE_INTERVAL=99999            # Interval to check for new logs (in seconds)
AUTO_UPDATE_WHITELIST_BOOL=false # Whether to automatically update the whitelist
AUTO_UPDATE_HOUR="00:00"         # Time of day to update the whitelist (24-hour format, e.g., "14:30" for 2:30 PM)
LOCAL_USER_AND_GROUP=""          # Ensure output files are accessible to this user, if specified; override in snort-monitor.conf if you wish, e.g. "www-data:www-data"

# Override this default prompt text in snort-monitor.conf if you wish:
read -r -d '' ANALYSIS_PROMPT_TEXT <<'EOF'
Role: You are an expert cybersecurity analyst.
Task: Analyze Snort/ntopng logs and provide a structured threat report.
Output Requirements using these section headings:
1. HIGHEST THREAT LEVEL REACHED
   Format: Single word (HIGH/MEDIUM/LOW/N/A) on its own line.
   Purpose: For automated parsing.
2. ASSESSMENT
   Content: A succinct but analytically advanced summary of urgency and bottom-line impact (3-4 sentences).
3. THREATS
   Format: Prioritized HTML table with colored cells (High=pale-red, Medium=pale-orange, Low=pale-green).
   Rules:
   - Explicitly list all IPs or domain names of concern; don't use 'e.g.' or shortcut phrases like 'and other IPs' as a way of skipping a complete enumeration.
   Columns: Threat Level, IP(s), Traffic Type, Justification.
4. TIMELINE
   Format: HTML table with time intervals (include day/month if not today).
5. NEXT STEPS
   Format: HTML bulleted list, priority-ordered (urgent first).
6. TECHNICAL DISCUSSION
   Content: Advanced and detailed technical analysis organized using the WASC threat classification and including advisory references.
   The goal is to educate an advanced reader on the nature of the threats and how they can be mitigated. Provide longer and more detailed description to advance this objective.
Styling & Compliance:
   Output Format: HTML only (no Markdown/JSON).
   Tables: Use pale red/orange/green backgrounds for High/Medium/Low.
   Consistency: Align threat levels across all sections.
EOF

# Override this default prompt text in snort-monitor.conf if you wish:
read -r -d '' BLOCKLIST_PROMPT_TEXT <<'EOF'
Role: You are an expert cybersecurity analyst.
Task: Generate a plain-text block list of external (routable) IP addresses for pfSense pfBlockerNG based on Snort/ntopng logs.
Requirements:
1. Scope: Only include external, routable IPs. 
2. Validation: Research each IP to avoid blocking trusted providers (e.g., Microsoft 365, Gmail).
3. Format: Plain text, one IP per line. No subnet masks, headers, or explanations.
4. Output Restrictions: No HTML/Markdown/JSON. Only raw IPs.
Example Output:
203.0.113.45
198.51.100.10
EOF

# Provide these default paths in snort-monitor.conf:
BLOCK_LIST_DIR="<provide BLOCK_LIST_DIR in .conf file>"                   # e.g., $SCRIPT_DIR/block-lists                               Directory to store block lists in
CONSOLIDATED_FILE_SHARE="<provide CONSOLIDATED_FILE_SHARE in .conf file>" # e.g., $SCRIPT_DIR/consolidated-block-list                   Consolidated block list directory (samba share)
CONSOLIDATED_FILE="<provide ONSOLIDATED_FILE in .conf file>"              # e.g., $CONSOLIDATED_FILE_SHARE/consolidated-block-list.txt  Consolidated block list file
WHITELIST_FILE="<provide WHITELIST_FILE in .conf file>"                   # e.g., $SCRIPT_DIR/ip-whitelist.txt                          IP whitelist file
REPORTS_DIR="<provide REPORTS_DIR in .conf file>"                         # e.g., $SCRIPT_DIR/reports                                   Directory to store PDF reports in
WEB_DIR="<provide WEB_DIR in .conf file>"                                 # e.g., /var/www/snort-monitor                               Directory for web files

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

TIMESTAMP_FILE="/tmp/last_snort_check.time" # File to store the last check timestamp
LOG_FILE="/var/log/snort-monitor.log"       # Log file for the script

# Update Interval and Pertubation variables
INTERVAL_PERTURBATION_MIN=0.8 # Minimum perturbation coefficient for interval
INTERVAL_PERTURBATION_MAX=1.4 # Maximum perturbation coefficient for interval
WEBPAGE_EXPIRATION_GRACE=10   # Grace period for webpage expiration allowing LLM API query/ies to take place (in seconds)

# Web server configuration
WEB_PORT=9999                  # Port for the Analysis web server
LOG_LINES_TO_SHOW=120          # Number of log lines to provide to the LLM and show on the webpage
BLOCK_LIST_WEB_PORT=9998       # Port for the Block List web server
DELETE_BLOCK_LISTS_AFTER=99999 # Number of days to keep the block list files before deleting them

# Execute custom initialization code if exists
if [[ -f "$SCRIPT_DIR/custom-init.sh" ]]; then
    source "$SCRIPT_DIR/custom-init.sh" >/dev/null 2>&1
fi

# Variables to store last analysis and Snort/ntopng log content
last_analysis=""
last_log_content=""
last_response=""
last_update_time=""

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

# -----------------------------------------------------------------------
# Function: save_PDF_report
# -----------------------------------------------------------------------
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
# -----------------------------------------------------------------------
#
save_PDF_report() {
    local threat_level="$1"
    shift
    local html_content="$*"

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

# -----------------------------------------------------------------------
# Function: create_webpage
# -----------------------------------------------------------------------
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
# -----------------------------------------------------------------------
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
        analysis="<p>No analysis available</p>" # Default analysis content
    fi
    if [ -z "$log_content" ]; then
        log_content="No log content available" # Default log content
    fi
    if [ -z "$api_response" ]; then
        api_response="No API response available" # Default API response content
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
    update_status+="<br>Snort logs last modified: $snort_log_updated_time_str <br>Webpage expires: $expire_time_str_short</p>"

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
            height: 200px;
            overflow-y: scroll;
            font-family: monospace;
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

    <div class="section-title">Last Successful API Response:</div>
    <div class="response-container">
        <div class="response-content">$api_response</div>
    </div>
</body>
</html>
EOF
}

# -----------------------------------------------------------------------
# Function: is_public_ip
# -----------------------------------------------------------------------
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
# -----------------------------------------------------------------------
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

# -----------------------------------------------------------------------
# Function: consolidate_ips
# -----------------------------------------------------------------------
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
# -----------------------------------------------------------------------
#
consolidate_ips() {
    # Create empty whitelist if file doesn't exist
    [ -f "$WHITELIST_FILE" ] || touch "$WHITELIST_FILE"

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
            mv "$CONSOLIDATED_FILE.tmp" "$CONSOLIDATED_FILE"
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

# Background monitoring function
start_monitor() {
    log "Starting block list monitor"

    # Initial cleanup of old files
    log "Performing initial cleanup of files older than $DELETE_BLOCK_LISTS_AFTER days"
    find "$BLOCK_LIST_DIR" -type f -mtime +"$DELETE_BLOCK_LISTS_AFTER" -delete -print | while read -r deleted_file; do
        log "Deleted old file: $deleted_file"
    done

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
                consolidate_ips
            fi
        done
}

# Cleanup function
cleanup() {
    kill "$MONITOR_PID" 2>/dev/null
    kill "$WHITELIST_UPDATER_PID" 2>/dev/null
    kill "$BLOCK_LIST_SERVER_PID" 2>/dev/null
    kill "$WEB_SERVER_PID" 2>/dev/null
    sleep 2

    # Check if the processes are still running
    if ps -p "$MONITOR_PID" >/dev/null; then
        log "Monitor process is still running, stopping it..."
        kill -9 "$MONITOR_PID"
    fi
    if ps -p "$WHITELIST_UPDATER_PID" >/dev/null; then
        log "Whitelist updater process is still running, stopping it..."
        kill -9 "$WHITELIST_UPDATER_PID"
    fi
    if ps -p "$BLOCK_LIST_SERVER_PID" >/dev/null; then
        log "Block list server process is still running, stopping it..."
        kill -9 "$BLOCK_LIST_SERVER_PID"
    fi
    if ps -p "$WEB_SERVER_PID" >/dev/null; then
        log "Web server process is still running, stopping it..."
        kill -9 "$WEB_SERVER_PID"
    fi
    sleep 2
    if ! ps -p "$MONITOR_PID" >/dev/null &&
        ! ps -p "$WHITELIST_UPDATER_PID" >/dev/null &&
        ! ps -p "$BLOCK_LIST_SERVER_PID" >/dev/null &&
        ! ps -p "$WEB_SERVER_PID" >/dev/null; then
        log "All background processes stopped successfully"
    else
        log "Some background processes failed to stop"
    fi
    log "**************** Exiting Snort Monitor Service ****************"
    exit 0
}

# -----------------------------------------------------------------------
# Function: update_analysis
# -----------------------------------------------------------------------
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
# -----------------------------------------------------------------------
#
update_analysis() {
    local expires_in="$(decode "$1")" # Web page expiration time in seconds

    local last_check=$(cat "$TIMESTAMP_FILE" 2>/dev/null || echo 0)               # Last time logs were checked
    local snort_log_updated_time=$(stat -c %Y "$SNORT_LOG" 2>/dev/null || echo 0) # Current modification time of the log file

    local analysis=""
    local cleaned_analysis=""
    local cleaned_response=""
    local response_no_extra_spaces=""
    local error=""
    local escaped_snort_log_lines=""
    local json_last_analysis=""
    local json_log_content=""
    local log_lines=""
    local log_lines_snort=""
    local log_lines_ntopng=""
    local request_json=""
    local response=""
    local time_now=$(date '+%Y-%m-%d %H:%M:%S')
    local normalized_html=""
    local highest_threat_level="N/A"
    local blocked_ips=$(paste -sd, "$CONSOLIDATED_FILE")

    local should_update="true"
    if [ "$snort_log_updated_time" -le "$last_check" ]; then
        log "No updates to Snort log since last check"
        should_update="false"
    else

        # Get snort log content
        log_lines_snort=$(tail -n "$LOG_LINES_TO_SHOW" "$SNORT_LOG")

        # resolve ntopng log lines with DNS addresses to IPs (not necessary if ntopng configured to not lookup numerical IPs)
        local temp_ntopng_in_file=$(mktemp)
        local temp_ntopng_out_file=$(mktemp)
        touch "$temp_ntopng_out_file"
        tail -n "$LOG_LINES_TO_SHOW" "$NTOPNG_LOG" >"$temp_ntopng_in_file"
        $SCRIPT_DIR/resolve-ntopng-log.sh "$temp_ntopng_in_file" "$temp_ntopng_out_file"
        log_lines_ntopng=$(cat "$temp_ntopng_out_file")
        rm -f "$temp_ntopng_in_file" "$temp_ntopng_out_file"

        log_lines=$(
            echo "Snort logs:\n"
            echo "$log_lines_snort"
            echo "ntopng logs:\n"
            echo "$log_lines_ntopng"
        )
        escaped_snort_log_lines=$(echo "$log_lines_snort" | escape_html)
        json_log_content=$(echo "$log_lines" | escape_json | tr -s ' ')
        json_last_analysis=""
        if [ -n "$last_analysis" ]; then
            json_last_analysis="\nThis is the last analysis you provided.  Please review it and use it as a guide for identifying patterns and making prioritizations and formating consistent over time:\n"
            json_last_analysis+=$(echo "$last_analysis" | escape_json)
        fi

        # Prepare the API request
        ANALYSIS_PROMPT_TEXT="${ANALYSIS_PROMPT_TEXT//<insert_date>/$time_now}"
        request_json=$(jq -n \
            --arg model "$MODEL" \
            --arg system_content "$ANALYSIS_PROMPT_TEXT" \
            --arg user_content "$json_log_content.  
            \nSUPPORTING MATERIALS:
            $json_last_analysis. 
            The following IPs have already been blocked: $blocked_ips." \
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
            max_tokens: 120000 
        }')

        echo "Last request JSON for Analysis:\n $request_json" >"$SCRIPT_DIR/last_analysis_request.log"

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

    create_webpage "$should_update" "$(encode $expires_in)" "$(encode $cleaned_analysis)" "$(encode $log_lines)" "$(encode $cleaned_response)" "$(encode $error)" "$(encode $snort_log_updated_time)"

    if [ "$should_update" = "true" ]; then
        # Save the report as a PDF
        save_PDF_report "$highest_threat_level" "$cleaned_analysis" &

        # Create a list of IPs to block
        # if [[ "$highest_threat_level" == "HIGH" ]] || [[ "$initial_consolidation" == "true" ]]; then
        (
            request_json=$(
                jq -n \
                    --arg model "$MODEL" \
                    --arg system_content "$BLOCKLIST_PROMPT_TEXT" \
                    --arg user_content "SUPPORTING MATERIALS:
Here is a recent threat analysis: $(echo $cleaned_analysis | tr -s ' ') \n
Here are some recent Snort and ntopng logs: $json_log_content \n
The following IPs have already been blocked: $blocked_ips" \
                    '{
                 model: $model,
                 messages: [
                   {role: "system", content: $system_content},
                   {role: "user",   content: $user_content}
                 ],
                 temperature: 0.1,
                 max_tokens: 120000
               }'
            )

            echo "Last request JSON for blocked IPs:\n $request_json" >"$SCRIPT_DIR/last_IPs_to_block_request.log"

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

                        local block_list_file="$BLOCK_LIST_DIR/block-list-$(date +%Y-%m-%d_%H-%M-%S).txt"
                        echo "$cleaned_block_list" >"$block_list_file"
                        log "Block list:"
                        log "$cleaned_block_list"
                        log "Block list saved to file $block_list_file"
                    fi
                fi
            else
                log "Block List request: Failed to connect to API. Exit code: $?"
            fi
        ) &
        # fi
    fi
}

# -----------------------------------------------------------------------
# Function: calculate_perturbed_interval
# -----------------------------------------------------------------------
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
# -----------------------------------------------------------------------
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

update_whitelist_runner() {
    # Background loop running task at AUTO_UPDATE_HOUR daily

    if [ "$AUTO_UPDATE_WHITELIST_BOOL" = true ]; then
        local script_output=""
        while true; do
            # Calculate now and next AUTO_UPDATE_HOUR
            now=$(date +%s)
            target=$(date -d "today $AUTO_UPDATE_HOUR" +%s)
            if ((now >= target)); then
                target=$(date -d "tomorrow $AUTO_UPDATE_HOUR" +%s)
            fi
            sleep $((target - now))

            log "Auto-updating whitelist now"
            echo "Running whitelist update script: $SCRIPT_DIR/extract-good-ips-from-block-list.sh"
            script_output="$($SCRIPT_DIR/extract-good-ips-from-block-list.sh)"
            log "Whitelist update script output: $script_output"
            echo "$script_output" >>"$SCRIPT_DIR/whitelist_update.log"
        done
    fi
}

# -----------------------------------------------------------------------
# Main execution performs the following tasks:
# -----------------------------------------------------------------------
# 1. Logs the start of the Snort Monitor Service.
# 2. Starts a web server in the background.
# 3. Waits for 2 seconds to ensure the web server is initialized.
# 4. Creates an initial webpage with default values indicating that the
#    first log analysis is pending.
#
# The script then enters an infinite loop where it:
# - Calculates a perturbed interval for the next analysis.
# - Computes the expiration time for the webpage based on the perturbed interval
#   and a predefined grace period allowing for the LLM API call and analysis to complete.
# - Updates the analysis webpage with the new expiration time.
# - Waits for the perturbed interval before repeating the process.
#
# Functions used:
# - log: Logs messages to a logging system.
# - start_web_server: Starts the web server in the background.
# - create_webpage: Generates the initial webpage with encoded parameters.
# - calculate_perturbed_interval: Computes a randomized interval for the next iteration.
# - update_analysis: Updates the analysis webpage with new data.
# - encode: Encodes data for safe usage in the webpage.
# -----------------------------------------------------------------------
#
log "**************** Starting Snort Monitor Service ****************"
log "Starting alert web server on port $WEB_PORT"
start_web_server &
ALERT_WEB_SERVER_PID=$!
sleep 2
create_webpage "false" "$(encode $WEBPAGE_EXPIRATION_GRACE)" "$(encode "Waiting for the first log analysis...")" "$(encode "Waiting for the first log analysis...")" "" "" ""

# Initial block list consolidation
first_time=true
consolidate_ips

# Start the whitelist updater in background
update_whitelist_runner &
WHITELIST_UPDATER_PID=$!

# Start the log monitor in background
start_monitor >/dev/null 2>&1 &
MONITOR_PID=$!

log "Starting block list web server on port $BLOCK_LIST_WEB_PORT"
share_block_list_via_HTTP &
BLOCK_LIST_WEB_SERVER_PID=$!

# Trap script exit to kill all background processes
trap cleanup EXIT

log "Alert Web server started with PID: $ALERT_WEB_SERVER_PID"
log "Block list monitor running (PID: $MONITOR_PID)"
log "Whitelist updater running (PID: $WHITELIST_UPDATER_PID)"
log "Block list web server running (PID: $BLOCK_LIST_WEB_SERVER_PID)"
log "Whitelist file: $WHITELIST_FILE"
log "Block-list file: $CONSOLIDATED_FILE"

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

    update_analysis "$(encode $expiration_time)"
    sleep "$perturbed_interval"
done
