#!/bin/bash
#
# ping.sh - ping sweep, port scan, banner grab
#
# Usage:
#   $0                  # default settings: scan local subnet, port 80, in table format
#   $0 192.168.1        # scan subnet 192.168.1.1-254
#   $0 192.168.1 8080   # scan subnet with custom port
#   $0 192.168.1.123    # scan single IP
#   $0 --port 443       # scan local subnet with port 443
#   $0 --csv            # CSV output
#   $0 --json           # JSON output
#   $0 --sort mac:down  # sort by MAC descending
#   $0 --help           # help
#
# All togeather: 
#   $0 192.168.1 8443 --json --sort mac:down
#

REQUIRED_CMDS=(ip ping nc awk grep cut sort xargs timeout curl openssl getent strings tr mktemp)
for CMD in "${REQUIRED_CMDS[@]}"; do
    command -v "$CMD" >/dev/null 2>&1 || { echo "Missing $CMD"; exit 1; }
done

CONCURRENCY=50
FIELDS=(ip hostname mac ttl time port info)
HEADER=("IP" "HOSTNAME" "MAC" "TTL" "TIME" "PORT" "INFO")
COLWIDTH=(16 32 18 4 8 4 0)

SORT_FIELD="ip"
SORT_ORDER="up"
FORMAT="text"
INPUT=""
PORT="80"
SCAN_MODE=""

for ((i=1; i<=$#; i++)); do
    eval ARG="\${$i}"
    eval NEXT="\${$((i+1))}"
    [[ "$ARG" == "--csv" ]] && FORMAT="csv"
    [[ "$ARG" == "--json" ]] && FORMAT="json"
    if [[ "$ARG" == --sort=* ]]; then
        VALUE="${ARG#--sort=}"
        SORT_FIELD="${VALUE%%:*}"
        SORT_ORDER="${VALUE##*:}"
        [[ "$SORT_ORDER" == "$SORT_FIELD" ]] && SORT_ORDER="up"
    elif [[ "$ARG" == "--sort" && "$NEXT" =~ ^[a-z]+(:up|:down)?$ ]]; then
        SORT_FIELD="${NEXT%%:*}"
        SORT_ORDER="${NEXT##*:}"
        [[ "$SORT_ORDER" == "$SORT_FIELD" ]] && SORT_ORDER="up"
    elif [[ "$ARG" == "--port" && "$NEXT" =~ ^[0-9]+$ ]]; then
        PORT="$NEXT"; ((i++))
    elif [[ "$ARG" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        INPUT="$ARG"; SCAN_MODE="single"
    elif [[ "$ARG" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        INPUT="$ARG"; SCAN_MODE="subnet"
    elif [[ "$ARG" =~ ^[0-9]+$ ]]; then
        PORT="$ARG"
    fi
done

if [[ -z "$INPUT" ]]; then
    IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)
    IPADDR=$(ip -4 addr show dev "$IFACE" | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
    [[ -z "$IPADDR" ]] && { echo "No subnet"; exit 1; }
    INPUT=$(echo "$IPADDR" | cut -d. -f1-3)
    SCAN_MODE="subnet"
    echo -e "\033[1;90m[*] Scanning $INPUT.1-254 on $IFACE\033[0m"
fi

DETECT_BANNER() {
    local IP="$1" PORT="$2" BANNER SERVICE TITLE CN EXP BODY CERT SERVER

    if curl -skL --max-time 3 "https://$IP:$PORT" -o /dev/null 2>&1; then
        SERVICE="https"
        TMPBODY=$(mktemp)
        curl -skL --max-time 3 "https://$IP:$PORT" > "$TMPBODY.raw"
        tr -d '\000' < "$TMPBODY.raw" > "$TMPBODY"
        BODY=$(cat "$TMPBODY")
        rm -f "$TMPBODY" "$TMPBODY.raw"
        SERVER=$(curl -skI --max-time 3 "https://$IP:$PORT" | grep -i '^Server:' | head -n1 | cut -d' ' -f2- | tr -d '\r\n')
        TMPCERT=$(mktemp)
        echo | timeout 3 openssl s_client -connect ${IP}:${PORT} -servername $IP 2>/dev/null > "$TMPCERT.raw"
        tr -d '\000' < "$TMPCERT.raw" > "$TMPCERT"
        CERT=$(cat "$TMPCERT")
        rm -f "$TMPCERT" "$TMPCERT.raw"
        CN=$(echo "$CERT" | openssl x509 -noout -subject 2>/dev/null | grep -oP 'CN\s*=\s*[^,]+' | cut -d= -f2 | tr -d ' ')
        EXP=$(echo "$CERT" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 | sed 's/^ *//')
    elif curl -sL --max-time 3 "http://$IP:$PORT" -o /dev/null 2>&1; then
        SERVICE="http"
        TMPBODY=$(mktemp)
        curl -sL --max-time 3 "http://$IP:$PORT" > "$TMPBODY.raw"
        tr -d '\000' < "$TMPBODY.raw" > "$TMPBODY"
        BODY=$(cat "$TMPBODY")
        rm -f "$TMPBODY" "$TMPBODY.raw"
        SERVER=$(curl -sI --max-time 3 "http://$IP:$PORT" | grep -i '^Server:' | head -n1 | cut -d' ' -f2- | tr -d '\r\n')
    fi

    if [[ "$BODY" ]]; then
        TITLE=$(echo "$BODY" | grep -iPo '(?<=<title>).*?(?=</title>)' | head -n1)
        if [[ "$TITLE" ]]; then
            [[ "$TITLE" =~ "plain HTTP request was sent to HTTPS port" ]] &&
                echo -ne "\033[1;32m[SERVER:HTTPS expected] \033[0m" ||
                echo -ne "\033[1;33m[TITLE:$TITLE] \033[0m"
        elif [[ "$SERVER" ]]; then
            echo -ne "\033[1;32m[SERVER:$SERVER] \033[0m"
        fi
        [[ "$CN" ]] && echo -ne "\033[1;36m[CN:$CN] \033[0m"
        [[ "$EXP" ]] && echo -ne "\033[1;35m[EXP:$EXP] \033[0m"
        return
    fi

    TMPBANNER=$(mktemp)
    timeout 7 bash -c "echo | nc -w 5 $IP $PORT 2>/dev/null" > "$TMPBANNER.raw"
    tr -d '\000' < "$TMPBANNER.raw" | LC_ALL=C strings | head -n2 > "$TMPBANNER"
    BANNER=$(cat "$TMPBANNER")
    rm -f "$TMPBANNER" "$TMPBANNER.raw"
    case "$BANNER" in
        *"SSH-"*) echo -ne "\033[1;34m[SSH:${BANNER%%$'\n'*}]\033[0m" ;;
        *"RFB"*) echo -ne "\033[1;34m[VNC:${BANNER%%$'\n'*}]\033[0m" ;;
        *"SMTP"*) echo -ne "\033[1;34m[SMTP:${BANNER%%$'\n'*}]\033[0m" ;;
        *"FTP"*) echo -ne "\033[1;34m[FTP:${BANNER%%$'\n'*}]\033[0m" ;;
        *"Telnet"*) echo -ne "\033[1;34m[Telnet]\033[0m" ;;
        *) [[ "$BANNER" ]] && echo -ne "\033[1;34m[BANNER:${BANNER%%$'\n'*}]\033[0m" ;;
    esac
}

PING_TARGET() {
    IP="$1"
    OUT=$(ping -c1 -W1 "$IP" 2>/dev/null) || exit
    HOST=$(getent hosts "$IP" | awk '{print $2}')
    MAC=$(ip neigh show "$IP" | awk '{print $5}')
    TTL=$(echo "$OUT" | grep -oE "ttl=[0-9]+" | cut -d= -f2)
    TIME=$(echo "$OUT" | grep -oE "time=[0-9.]+ ms" | cut -d= -f2)
    if nc -z -w1 "$IP" "$PORT" &>/dev/null; then
        OPEN="yes"
        DETAILS=$(DETECT_BANNER "$IP" "$PORT")
    else
        OPEN="--"
        DETAILS=""
    fi
    echo -e "$IP\t${HOST:--}\t${MAC:--}\t${TTL:--}\t${TIME:--}\t$OPEN\t$DETAILS"
}

export -f PING_TARGET
export -f DETECT_BANNER
export PORT

GENERATE_IPS() {
    if [[ "$SCAN_MODE" == "single" ]]; then echo "$INPUT"
    else for I in $(seq 1 254); do echo "$INPUT.$I"; done
    fi
}

TMPFILE=$(mktemp)
GENERATE_IPS | xargs -I{} -P "$CONCURRENCY" bash -c 'PING_TARGET "{}"' >> "$TMPFILE"

SORT_OUTPUT() {
    local idx field="$1" order="$2"
    idx=$(printf "%s\n" "${FIELDS[@]}" | grep -n -Fx "$field" | cut -d: -f1)
    [[ -z "$idx" ]] && { cat "$TMPFILE"; return; }
    case "$field" in
        ip)
            awk -F'\t' -v idx="$idx" '{
                split($idx, a, "."); 
                printf("%03d.%03d.%03d.%03d\t", a[1], a[2], a[3], a[4]);
                for(i=1;i<=NF;++i) if(i!=idx) printf "%s\t", $i;
                print ""
            }' "$TMPFILE" | \
            { [[ "$order" == "down" ]] && sort -k1,1r || sort -k1,1; } |
            sed -E 's/^0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)\t/\1.\2.\3.\4\t/'
            ;;
        mac)
            awk -F'\t' -v idx="$idx" '{
                n=split($idx, a, ":"); macstr="";
                for(j=1;j<=n;++j) macstr=macstr sprintf("%02X", strtonum("0x"a[j]));
                print macstr "\t" $0
            }' "$TMPFILE" | \
            { [[ "$order" == "down" ]] && sort -k1,1r || sort -k1,1; } | cut -f2-
            ;;
        ttl|time|port)
            [[ "$order" == "down" ]] && sort -t$'\t' -k"$idx" -nr "$TMPFILE" || sort -t$'\t' -k"$idx" -n "$TMPFILE"
            ;;
        *)
            [[ "$order" == "down" ]] && sort -t$'\t' -k"$idx" -r "$TMPFILE" || sort -t$'\t' -k"$idx" "$TMPFILE"
            ;;
    esac
}

OUTPUT=$(SORT_OUTPUT "$SORT_FIELD" "$SORT_ORDER")

NC='\033[0m'
WH='\033[1;37m'
GY='\033[0;90m'
GR='\033[0;32m'
UP='↑'
DOWN='↓'

for idx in "${!HEADER[@]}"; do
    ARROW=""
    if [[ "${FIELDS[$idx]}" == "$SORT_FIELD" ]]; then
        COL="$WH"
        [[ "$SORT_ORDER" == "up" ]] && ARROW=" $UP"
        [[ "$SORT_ORDER" == "down" ]] && ARROW=" $DOWN"
    else COL="$GY"; fi
    w=${COLWIDTH[$idx]}
    [[ $w -gt 0 ]] && printf "${COL}%-${w}s${NC} " "${HEADER[$idx]}${ARROW}" || printf "${COL}%s${NC} " "${HEADER[$idx]}${ARROW}"
done
printf "\n"

if [[ "$FORMAT" == "json" ]]; then
    echo "$OUTPUT" | awk -F'\t' 'BEGIN { print "[" }
    { printf "  {\"ip\":\"%s\", \"hostname\":\"%s\", \"mac\":\"%s\", \"ttl\":\"%s\", \"time\":\"%s\", \"port\":\"%s\", \"info\":\"%s\"}", $1,$2,$3,$4,$5,$6,$7
      if (NR != NR_END) print ","; else print "" }
    END { print "]" }' NR_END=$(wc -l < "$TMPFILE")
elif [[ "$FORMAT" == "csv" ]]; then
    echo "ip,hostname,mac,ttl,time,port,info"
    echo "$OUTPUT" | awk -F'\t' '{printf "%s,%s,%s,%s,%s,%s,%s\n", $1,$2,$3,$4,$5,$6,$7}'
else
    echo "$OUTPUT" | awk -F'\t' -v gr="$GR" -v nc="$NC" '{ port=$6=="yes"?gr "yes" nc:$6; printf "%-16s %-32s %-18s %-4s %-8s %-4s %s\n", $1,$2,$3,$4,$5,port,$7 }'
fi

rm -f "$TMPFILE"
