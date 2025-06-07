#!/bin/bash
# restart snort-monitor service and force regeneration of the Alert Monitor report

# Source the configuration file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCRIPT_DIR
if [[ -f "$SCRIPT_DIR/snort-monitor.conf" ]]; then
    source "$SCRIPT_DIR/snort-monitor.conf"
else
    echo "Configuration file snort-monitor.conf not found in $SCRIPT_DIR" >&2
fi

echo "This script restarts the snort-monitor service and artificially updates the modified time on the snort log file"
echo "so that the Alert Monitor report is regenerated."
echo "----------------------------------------------------------------------------------------------------------------------"
sudo systemctl stop snort-monitor.service > /dev/null 2>&1
sleep 2
echo -n "1- Restarting snort-monitor service "
sudo systemctl start snort-monitor.service > /dev/null 2>&1
for i in {1..12}; do
    echo -n "."
    sleep 1
done
echo ""
echo "2- Touching the Snort log file to update its modified time"
sudo touch "$SNORT_LOG"
echo -n "3- Waiting for the Alert Monitor report to be regenerated "
for i in {1..30}; do
    echo -n "."
    sleep 1
done
echo ""
echo "Done: You can now check for new Alert Monitor report..." 