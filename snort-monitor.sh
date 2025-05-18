#!/bin/bash
# -----------------------------------------------------------------------------
# snort-monitor.sh
#
# Overview:
#   This script provides a comprehensive monitoring and analysis solution for
#   Snort and ntopng logs. It periodically analyzes log files, generates
#   prioritized threat summaries using the OpenAI API, and serves the results
#   as a dynamic web page. The script also manages block lists, consolidates
#   IPs for firewall blocking, and provides PDF reporting.
#
# Features:
#   - Periodic analysis of Snort and ntopng logs with configurable intervals.
#   - Integration with OpenAI API for advanced threat analysis and recommendations.
#   - Dynamic HTML web page generation with threat summaries and log content.
#   - Simple Python-based HTTP server with cache control for serving the web page.
#   - Automated block list consolidation and sharing via HTTP.
#   - PDF report generation of each analysis.
#   - Graceful error handling and automatic retries for API and server failures.
#
# Configuration:
#   - SNORT_LOG: Path to the Snort log file (from snort-monitor.conf).
#   - NTOPNG_LOG: Path to the ntopng log file (from snort-monitor.conf).
#   - API_ENDPOINT: OpenAI API endpoint (from snort-monitor.conf).
#   - API_KEY: OpenAI API key (from snort-monitor.conf).
#   - MODEL: OpenAI model to use (from snort-monitor.conf).
#   - WEB_DIR: Directory for web files.
#   - TIMESTAMP_FILE: File to store the last check timestamp.
#   - LOG_FILE: Log file for the script.
#   - BLOCK_LIST_DIR: Directory for block lists.
#   - CONSOLIDATED_FILE_SHARE: Directory for consolidated block list (Samba share).
#   - CONSOLIDATED_FILE: Consolidated block list file.
#   - WHITELIST_FILE: IP whitelist file.
#   - REPORTS_DIR: Directory for PDF reports.
#   - UPDATE_INTERVAL: Base interval for log analysis (seconds).
#   - INTERVAL_PERTURBATION_MIN/MAX: Perturbation range for randomized intervals.
#   - WEBPAGE_EXPIRATION_GRACE: Grace period for webpage expiration (seconds).
#   - WEB_PORT: Port for the analysis web server.
#   - LOG_LINES_TO_SHOW: Number of log lines to analyze and display.
#   - BLOCK_LIST_WEB_PORT: Port for the block list web server.
#
# Dependencies:
#   - Bash shell
#   - Python 3 (for HTTP server)
#   - jq (for JSON processing)
#   - curl (for API requests)
#   - wkhtmltopdf (for PDF reports)
#   - inotifywait (for directory monitoring)
#
# Main Functions:
#   - log: Logs messages with timestamps.
#   - escape_json: Escapes strings for JSON safety.
#   - escape_html: Escapes HTML special characters.
#   - encode/decode: Base64 encode/decode for safe parameter passing.
#   - remove_backticks: Cleans up code block formatting from strings.
#   - start_web_server: Runs the Python HTTP server for the web UI.
#   - share_block_list_via_HTTP: Serves the consolidated block list via HTTP.
#   - save_PDF_report: Saves analysis as a PDF report.
#   - create_webpage: Generates the HTML web page for analysis results.
#   - is_public_ip: Checks if an IP is public/routable.
#   - consolidate_ips: Consolidates and deduplicates block list IPs, applies whitelist.
#   - start_monitor: Monitors block list directory for changes and triggers consolidation.
#   - cleanup: Handles script exit and cleanup.
#   - update_analysis: Performs log analysis, calls API, updates web page, manages block list.
#   - calculate_perturbed_interval: Computes randomized analysis intervals.
#
# Usage:
#   1. Configure snort-monitor.conf with correct paths and API credentials.
#   2. Run the script to start monitoring and serving the web page.
#   3. Access the analysis at http://<server-ip>:<WEB_PORT>.
#   4. Access the consolidated block list at http://<server-ip>:<BLOCK_LIST_WEB_PORT>.
#
# Notes:
#   - The script is designed for continuous operation and resilience.
#   - All generated files and logs are managed in specified directories.
#   - The web page and block list are automatically refreshed and updated.
# -----------------------------------------------------------------------------
#
# Shellcheck directives
# shellcheck disable=SC2155
# shellcheck disable=SC2181
# shellcheck disable=SC1091
# shellcheck disable=SC2086
# shellcheck disable=SC2001

# Configuration variables
SNORT_LOG=""    # Path to the snort log file (sourced from snort-monitor.conf
NTOPNG_LOG=""   # Path to the ntopng log file (sourced from snort-monitor.conf)
API_ENDPOINT="" # OpenAI API endpoint (sourced from snort-monitor.conf)
API_KEY=""      # OpenAI API key (sourced from snort-monitor.conf)
MODEL=""        # OpenAI model to use (sourced from snort-monitor.conf)

# Source the configuration file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/snort-monitor.conf"

WEB_DIR="/var/www/snort-monitor"                                                       # Directory for web files
TIMESTAMP_FILE="/tmp/last_snort_check.time"                                            # File to store the last check timestamp
LOG_FILE="/var/log/snort-monitor.log"                                                  # Log file for the script
BLOCK_LIST_DIR="$SCRIPT_DIR/block-lists"                                               # Directory to store block lists in
CONSOLIDATED_FILE_SHARE="$SCRIPT_DIR/consolidated-block-list"                          # Consolidated block list directory (samba share)
CONSOLIDATED_FILE="$CONSOLIDATED_FILE_SHARE/consolidated-block-list.txt"               # Consolidated block list file
# WhoAmI functionality moved to separate script
# CONSOLIDATED_FILE_WHOAMI="$CONSOLIDATED_FILE_SHARE/consolidated-block-list-whoami.csv" # Consolidated block list file
WHITELIST_FILE="$SCRIPT_DIR/ip-whitelist.txt"                                          # IP whitelist file
REPORTS_DIR="$SCRIPT_DIR/reports"                                                      # Directory to store PDF reports in

# Update Interval and Pertubation variables
UPDATE_INTERVAL=600           # Interval to check for new logs (in seconds)
INTERVAL_PERTURBATION_MIN=0.8 # Minimum perturbation coefficient for interval
INTERVAL_PERTURBATION_MAX=1.4 # Maximum perturbation coefficient for interval
WEBPAGE_EXPIRATION_GRACE=10   # Grace period for webpage expiration allowing LLM API query/ies to take place (in seconds)

# Web server configuration
WEB_PORT=9999              # Port for the Analysis web server
LOG_LINES_TO_SHOW=120      # Number of log lines to provide to the LLM and show on the webpage
BLOCK_LIST_WEB_PORT=9998   # Port for the Block List web server
DELETE_BLOCK_LISTS_AFTER=5 # Number of days to keep the block list files before deleting them

# Variables to store last analysis and Snort/ntopng log content
last_analysis=""
last_log_content=""
last_response=""
last_update_time=""

# Flag for initial consolidation of the block list
initial_consolidation=true

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
# Saves the Snort alert monitoring analysis as a PDF report.
# The function takes the following parameters:
#
# Parameters:
#   threat_level: The threat level of the analysis (e.g., "HIGH", "MEDIUM", "LOW").
#   html_content: The HTML content to include in the PDF report.
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
# Generates an HTML webpage to display the Snort alert monitoring analysis.
# The function takes the following parameters:
#
# Parameters:
#   $1 (updated): A flag indicating whether the webpage is being updated ("true" or "false").
#   $2 (expire_secs): The expiration time of the webpage in seconds (base64 encoded).
#   $3 (analysis): The analysis content to display on the webpage (base64 encoded).
#   $4 (log_content): The Snort log content to display on the webpage (base64 encoded).
#   $5 (api_response): The last successful API response content (base64 encoded).
#   $6 (error): An error message to display if applicable (base64 encoded).
#   $7 (snort_log_updated_time): The last modification time of the Snort logs (UNIX timestamp, base64 encoded).
#
# Behaviour:
# - Decodes the base64-encoded inputs using the `decode` function.
# - If no analysis, log content, or API response is provided, default messages are used.
# - If the webpage is not being updated (`updated` is "false"), it reuses the last known
#   analysis, log content, and API response, along with the last update time.
# - If the webpage is being updated (`updated` is "true"), it updates the last known
#   values and sets the current update time.
# - Calculates the expiration time of the webpage in both GMT and local formats.
# - Formats the Snort log last updated time, displaying "n/a" if the timestamp is invalid
#   or before 2010.
# - Generates an HTML file at `$WEB_DIR/index.html` with the following sections:
#   - A header displaying the last analysis time, Snort log modification time, and webpage expiration time.
#   - The analysis content.
#   - The recent Snort logs (up to `$LOG_LINES_TO_SHOW` lines).
#   - The last successful API response.
# - Includes inline CSS for styling the webpage.
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
    local snort_log_updated_time_str=""
    if [ "$snort_log_updated_time" -le 1262304000 ]; then
        snort_log_updated_time_str="n/a"
    else
        snort_log_updated_time_str=$(date -d @$snort_log_updated_time '+%Y-%m-%d %H:%M:%S')
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
    <div class="section-title">Recent Snort Logs (last $LOG_LINES_TO_SHOW lines):</div>
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
# Checks if the given IP address is a public IPv4 address.
# Arguments:
#   $1 - The IP address to check.
# Returns:
#   0 if the IP address is public, 1 otherwise.
# Notes:
#   - Returns 1 if the IP is not a valid IPv4 address.
#   - Considers the following ranges as non-public (private, loopback, link-local, or reserved):
#       10.0.0.0/8
#       172.16.0.0/12
#       192.168.0.0/16
#       169.254.0.0/16
#       127.0.0.0/8
#       100.64.0.0/10 (Carrier-grade NAT)
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
# Functions: consolidate_ips & create_whoami_file
# -----------------------------------------------------------------------
# Consolidates IP addresses from multiple block list files, applies a whitelist, and outputs a deduplicated, sorted list.
# The second function creates a WHOAMI file with DNS and organization information for each IP.
#
# Steps performed:
# 1. Ensures the whitelist file exists.
# 2. Extracts all IPv4 addresses from files in the block list directory.
# 3. Filters out invalid IP addresses (ensures each octet is between 0 and 255).
# 4. Removes any IPs present in the whitelist.
# 5. Sorts the resulting IPs numerically and removes duplicates.
# 6. Atomically updates the consolidated block list file.
# 7. Cleans up temporary files used during processing.
#
# Globals required:
#   - WHITELIST_FILE: Path to the whitelist file.
#   - BLOCK_LIST_DIR: Directory containing block list files.
#   - CONSOLIDATED_FILE: Output file for the consolidated IP list.
#   - log: Function for logging messages.
#

# create_whoami_file() {
#     # Create/clear the output file with CSV header
#     echo "IP Address,DNS Name,Organization" >"$CONSOLIDATED_FILE_WHOAMI"

#     # Skip if no IPs to process
#     [ ! -f "$CONSOLIDATED_FILE" ] && return

#     # Process each IP in the consolidated file
#     while read -r ip; do
#         # Perform DNS reverse lookup (with timeout)
#         dns_name=$(timeout 2 dig +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//')
#         [ -z "$dns_name" ] && dns_name="N/A"

#         # Get organization info from WHOIS (with timeout)
#         org_info=$(timeout 2 whois "$ip" 2>/dev/null |
#             awk -F':' '/^OrgName:|^descr:|^owner:|^netname:/ {print $2; exit}' |
#             sed 's/^ *//;s/ *$//')
#         [ -z "$org_info" ] && org_info="N/A"

#         # Append to CSV file
#         echo "\"$ip\",\"$dns_name\",\"$org_info\"" >>"$CONSOLIDATED_FILE_WHOAMI"
#     done <"$CONSOLIDATED_FILE"

#     log "Created WHOAMI file with DNS information"
# }

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
            log "Consolidated block list updated"
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
    # create_whoami_file &
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
    echo "$(date) - Stopped block list monitor" >>"$LOG_FILE"
    exit 0
}

# -----------------------------------------------------------------------
# Function: update_analysis
# -----------------------------------------------------------------------
# Updates the analysis of Snort logs by performing the following steps:
# 1. Checks if the Snort log file has been updated since the last analysis.
# 2. Reads the latest log entries and formats them for API submission.
# 3. Sends the log data to an external API for analysis, requesting a prioritized
#    summary of threats, threat levels, timelines, and recommended actions.
# 4. Handles the API response, extracting and cleaning the analysis results.
# 5. Generates a web page displaying the analysis, log content, and any errors.
# 6. Updates the timestamp of the last analysis to avoid redundant processing.
#
# Parameters:
# - $1: Encoded expiration time for the web page in seconds.
#
# Dependencies:
# - Requires external tools such as `jq`, `curl`, and `awk`.
# - Relies on environment variables like $TIMESTAMP_FILE, $SNORT_LOG, $MODEL,
#   $API_ENDPOINT, $API_KEY, $LOG_LINES_TO_SHOW, and $last_analysis.
#
# Outputs:
# - Creates or updates a web page with the analysis results.
# - Logs success or error messages to the system log.
#
update_analysis() {
    local expires_in="$(decode "$1")" # Web page expiration time in seconds

    local last_check=$(cat "$TIMESTAMP_FILE" 2>/dev/null || echo 0)               # Last time logs were checked
    local snort_log_updated_time=$(stat -c %Y "$SNORT_LOG" 2>/dev/null || echo 0) # Current modification time of the log file

    local analysis=""
    local cleaned_analysis=""
    local cleaned_response=""
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

    local should_update="true"
    if [ "$snort_log_updated_time" -le "$last_check" ]; then
        log "No updates to Snort log since last check"
        should_update="false"
    else

        # Get and properly format log content
        log_lines_snort=$(tail -n "$LOG_LINES_TO_SHOW" "$SNORT_LOG")
        log_lines_ntopng=$(tail -n "$LOG_LINES_TO_SHOW" "$NTOPNG_LOG")
        log_lines=$(
            echo "Snort logs:"
            echo "$log_lines_snort"
            echo "ntopng logs:"
            echo "$log_lines_ntopng"
        )
        escaped_snort_log_lines=$(echo "$log_lines_snort" | escape_html)
        json_log_content=$(echo "$log_lines" | escape_json)
        json_last_analysis=""
        if [ -n "$last_analysis" ]; then
            json_last_analysis="This is the last analysis you provided.  Please review it and use it as a guide for identifying patterns and making prioritizations and formating consistent over time: "
            json_last_analysis+=$(echo "$last_analysis" | escape_json)
        fi

        # Prepare the API request
        request_json=$(jq -n \
            --arg model "$MODEL" \
            --arg system_content "You are an expert cybersecurity analyst. Correlate and fully analyze the following recent logs from Snort and ntopng and provide:
1. HIGHEST THREAT LEVEL REACHED: Comprises a single word on the next line, either HIGH, MEDIUM, LOW or N/A (for no threat level), indicating the highest threat level reported in the analysis that follows. This will be parsed later by automation.
2. ASSESSMENT: A succinct summary of the bottom line and a sense of what the urgency is.
3. THREATS: A prioritized table of threats organized by threat levels (High/Medium/Low), noting which IPs are involved.
4. TIMELINE: a timeline of the threats, indicating time intervals during which they occurred (include the day of the month in these intervals if not all times are from today, $time_now).
5. NEXT STEPS: A bulleted list of recommended next steps, including any actions to take and any additional information needed, sorted by priorty with the most urgent coming first.
6. TECHNICAL DISCUSSION: An advanced-level technical discussion of the threats observed providing relevant technical explanations and background, 
a technical description of what could explain the occurences, and a technical justification for the prioritization. 
Please format as HTML for visually appealing web display. Avoid special characters that may not appear properly in the browser. Do not use any Markdown.
Please use tables with background cell colors denoting priority, with high priority indicated by a background of pale red, medium by pale orange, and low by pale green. 
Please ensure prioritizations are used consistently for the same items throughout your response." \
            --arg user_content "$json_log_content. Context: $json_last_analysis" \
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
            max_tokens: 90000 
        }')

        # Call the API with a request for an analysis
        response=$(curl -s -X POST "$API_ENDPOINT" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $API_KEY" \
            -d "$request_json")

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
    create_webpage "$should_update" "$(encode $expires_in)" "$(encode $cleaned_analysis)" "$(encode $escaped_snort_log_lines)" "$(encode $cleaned_response)" "$(encode $error)" "$(encode $snort_log_updated_time)"

    if [ "$should_update" = "true" ]; then
        # Save the report as a PDF
        save_PDF_report "$highest_threat_level" "$cleaned_analysis" &

        # Create a list of IPs to block
        # if [[ "$highest_threat_level" == "HIGH" ]] || [[ "$initial_consolidation" == "true" ]]; then
        (
            # Prepare the API request
            request_json=$(jq -n \
                --arg model "$MODEL" \
                --arg system_content "You are an expert cybersecurity analyst. Based on the following threat analysis and logs from Snort and ntopng, provide a comprehensive list of
            external (routable) IP addresses that should be blocked at the firewall level by pfSense.  No internal (non-routable) IP addresses should be included in the list.
            The list should be formatted as a plain text list of IPs, one per line, with no subnetwork masking (list each IP individually on its own line). Do not respond with any other text or explanation. Please make sure your output is NOT formatted as HTML, Markdown or JSON. It should be strictly plain text." \
                --arg user_content "Threat Analsys: $cleaned_analysis. Logs: $json_log_content" \
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
            temperature: 0.1,
            max_tokens: 90000 
        }')
            response=$(curl -s -X POST "$API_ENDPOINT" \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer $API_KEY" \
                -d "$request_json")

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
# Calculates a randomized refresh interval for updating the analysis. This helps
# to avoid predictable update patterns and increases the randomness of LLM API calls
# by introducing a perturbation factor.
#
# Steps:
# 1. Generates a random perturbation factor within a specified range.
# 2. Multiplies the base update interval by the perturbation factor.
# 3. Ensures the resulting interval is greater than zero.
#
# Dependencies:
# - Requires the `awk` command-line tool.
# - Relies on environment variables $INTERVAL_PERTURBATION_MIN, $INTERVAL_PERTURBATION_MAX,
#   and $UPDATE_INTERVAL.
#
# Outputs:
# - Prints the calculated refresh interval (in seconds) to standard output.
# Function to update the analysis
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

# Main execution performs the following tasks:
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
#
log "Starting Snort Monitor Service"
start_web_server &
sleep 2

create_webpage "false" "$(encode $WEBPAGE_EXPIRATION_GRACE)" "$(encode "Waiting for the first log analysis...")" "$(encode "Waiting for the first log analysis...")" "" "" ""

first_time=true

# Initial block list consolidation
consolidate_ips

# Start the monitor in background
start_monitor >/dev/null 2>&1 &
MONITOR_PID=$!

# Trap script exit to kill the monitor
trap cleanup EXIT

log "Block list monitor running (PID: $MONITOR_PID)"
log "Consolidated output: $CONSOLIDATED_FILE"

log "Starting block list web server on port $BLOCK_LIST_WEB_PORT"
share_block_list_via_HTTP &

# Main loop
while true; do
    if $first_time; then
        first_time=false
        expiration_time=20
        perturbed_interval=15
    else
        perturbed_interval=$(calculate_perturbed_interval)
        expiration_time=$(printf "%.0f" "$((perturbed_interval + WEBPAGE_EXPIRATION_GRACE))")
    fi

    update_analysis "$(encode $expiration_time)"
    sleep "$perturbed_interval"
done
