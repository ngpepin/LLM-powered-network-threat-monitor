#!/bin/bash

IN_FILE="$1"  
IN_FILE_NOEXT="${IN_FILE%.*}"
OUT_FILE="${IN_FILE_NOEXT}_IPs.log"                                     

./resolve-ntopng-log.sh "$IN_FILE" "$OUT_FILE"
./ntopng-log-to-csv.sh "$OUT_FILE"