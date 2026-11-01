#!/usr/bin/env bash

set -o pipefail

DNS="10.0.100.1"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FOLDER="$SCRIPT_DIR/blocklists"
OUTPUT="$SCRIPT_DIR/resolved-domains.csv"

TMP=""
PID=""

format_time() {
    local seconds="$1"
    printf '%02d:%02d:%02d' \
        "$((seconds / 3600))" \
        "$(((seconds % 3600) / 60))" \
        "$((seconds % 60))"
}

cleanup() {
    if [[ -n "$TMP" && -d "$TMP" ]]; then
        rm -rf -- "$TMP"
    fi
}

stop_workers() {
    echo
    echo "Stopping DNS workers..."
    if [[ -n "$PID" ]]; then
        kill -TERM "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
        PID=""
    fi
    exit 130
}

read -r -p "Number of parallel workers (default 30): " WORKERS
WORKERS="${WORKERS:-30}"

if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || (( WORKERS < 1 )); then
    echo "ERROR: Invalid worker count."
    exit 1
fi

for cmd in dig awk sort find xargs flock mktemp; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Missing command: $cmd"
        echo "Install with: sudo apt install dnsutils util-linux"
        exit 1
    fi
done

if [[ ! -d "$FOLDER" ]]; then
    echo "ERROR: Blocklists folder not found: $FOLDER"
    exit 1
fi

TMP="$(mktemp -d)" || exit 1
trap cleanup EXIT
trap stop_workers INT TERM

export DNS TMP

echo
echo "DNS server: $DNS"
echo "Blocklists: $FOLDER"
echo "Workers: $WORKERS"
echo "Sort memory limit: 64 MB"
echo

# STEP 1: Extract domains

echo "Extracting domains..."

: > "$TMP/raw"

while IFS= read -r -d '' file; do

    source_name="${file#"$FOLDER"/}"

    awk -v source="$source_name" '
    {
        sub(/\r$/, "")

        if ($0 ~ /^[[:space:]]*#/) next

        sub(/[[:space:]]+#.*/, "")
        gsub(/^[[:space:]]+|[[:space:]]+$/, "")

        if ($0 == "" || substr($0, 1, 1) == "!") next
        if (substr($0, 1, 2) == "@@") next

        split($0, parts, /[[:space:]]+/)

        if (parts[1] ~ /^(0\.0\.0\.0|127\.0\.0\.1|::|::1)$/) {
            domain = parts[2]
        } else {
            domain = parts[1]
            sub(/^\|\|/, "", domain)
            sub(/^\*\./, "", domain)
            sub(/[\^$\/].*/, "", domain)
        }

        domain = tolower(domain)
        sub(/\.$/, "", domain)

        if (domain ~ /^[a-z0-9][a-z0-9.-]*\.[a-z][a-z]+$/ && domain !~ /\.\./) {
            print domain "\t" source
        }
    }' "$file" >> "$TMP/raw"

done < <(find "$FOLDER" -type f -print0)

if [[ ! -s "$TMP/raw" ]]; then
    echo "ERROR: No domains extracted."
    exit 1
fi

echo "Sorting domains (64 MB sort memory)..."

LC_ALL=C sort -S 64M -T "$TMP" -u "$TMP/raw" > "$TMP/input" || {
    echo "ERROR: Sorting failed."
    exit 1
}

rm -f "$TMP/raw"

TOTAL="$(wc -l < "$TMP/input")"

if (( TOTAL == 0 )); then
    echo "ERROR: No valid domains found."
    exit 1
fi

echo "Total domain/source combinations: $TOTAL"

# STEP 2: Prepare jobs

awk -F '\t' '{ printf "%s%c%s%c", $1, 0, $2, 0 }' \
    "$TMP/input" > "$TMP/jobs" || exit 1

rm -f "$TMP/input"

touch "$TMP/resolved" "$TMP/lock"
printf '0 0 0 0\n' > "$TMP/stats"

exec 9>"$TMP/lock"

# STEP 3: Separate worker script

cat > "$TMP/worker.sh" <<'WORKER'
#!/usr/bin/env bash

domain="$1"
source_name="$2"

A_RESULT="$(dig @"$DNS" "$domain" A +noall +comments +answer +time=2 +tries=1 2>/dev/null)"
AAAA_RESULT="$(dig @"$DNS" "$domain" AAAA +noall +comments +answer +time=2 +tries=1 2>/dev/null)"

A_STATUS="$(sed -n 's/.*status: \([^,]*\),.*/\1/p' <<< "$A_RESULT" | head -n 1)"
AAAA_STATUS="$(sed -n 's/.*status: \([^,]*\),.*/\1/p' <<< "$AAAA_RESULT" | head -n 1)"

VALID_A="$(awk '$4 == "A" {print $5}' <<< "$A_RESULT" |
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' |
    grep -Ev '^(0\.0\.0\.0|127\.)' | head -n 1)"

VALID_AAAA="$(awk '$4 == "AAAA" {print $5}' <<< "$AAAA_RESULT" |
    grep ':' | grep -Ev '^::$|^::1$' | head -n 1)"

A_SINK=false
AAAA_SINK=false

grep -Eq 'IN[[:space:]]+A[[:space:]]+0\.0\.0\.0$' <<< "$A_RESULT" && A_SINK=true
grep -Eq 'IN[[:space:]]+AAAA[[:space:]]+::$' <<< "$AAAA_RESULT" && AAAA_SINK=true

if [[ -n "$VALID_A" || -n "$VALID_AAAA" ]]; then
    CLASS="BYPASSED"

elif [[ "$A_STATUS" == "NXDOMAIN" && "$AAAA_STATUS" == "NXDOMAIN" ]] ||
     { [[ "$A_SINK" == true ]] && [[ "$AAAA_SINK" == true ]]; }; then
    CLASS="BLOCKED"

else
    CLASS="UNKNOWN"
fi

exec 9>>"$TMP/lock"
flock -x 9

read -r completed bypassed blocked unknown < "$TMP/stats"

((completed += 1))

case "$CLASS" in

    BYPASSED)
        ((bypassed += 1))

        printf '"%s","%s","%s","%s"\n' \
            "${domain//\"/\"\"}" \
            "${source_name//\"/\"\"}" \
            "$VALID_A" "$VALID_AAAA" >> "$TMP/resolved"
        ;;

    BLOCKED)
        ((blocked += 1))
        ;;

    UNKNOWN)
        ((unknown += 1))
        ;;

esac

printf '%s %s %s %s\n' \
    "$completed" "$bypassed" "$blocked" "$unknown" \
    > "$TMP/stats"

flock -u 9
WORKER

chmod +x "$TMP/worker.sh"

# STEP 4: Start parallel DNS testing

echo
echo "Starting DNS tests..."

START=$SECONDS

xargs -0 -r -P "$WORKERS" -n 2 \
    bash "$TMP/worker.sh" < "$TMP/jobs" &

PID=$!

# STEP 5: Live progress

while kill -0 "$PID" 2>/dev/null; do

    flock -s 9
    read -r COMPLETED BYPASSED BLOCKED UNKNOWN < "$TMP/stats"
    flock -u 9

    ELAPSED=$((SECONDS - START))
    REMAINING=$((TOTAL - COMPLETED))

    if (( COMPLETED > 0 )); then

        AVG="$(awk -v t="$ELAPSED" -v n="$COMPLETED" \
            'BEGIN {printf "%.3f", t/n}')"

        SPEED="$(awk -v n="$COMPLETED" -v t="$ELAPSED" \
            'BEGIN {if (t>0) printf "%.1f", n/t; else print "0"}')"

        ETA=$((REMAINING * ELAPSED / COMPLETED))
        ETA_TEXT="$(format_time "$ETA")"

    else

        AVG="Calculating"
        SPEED="0"
        ETA_TEXT="Calculating"

    fi

    PERCENT=$((COMPLETED * 100 / TOTAL))

    printf '\rProgress: %s%% | Scanned: %s/%s | Remaining: %s | Bypassed: %s | Blocked: %s | Unknown: %s | Speed: %s/s | Avg: %s s | ETA: %s' \
        "$PERCENT" "$COMPLETED" "$TOTAL" "$REMAINING" \
        "$BYPASSED" "$BLOCKED" "$UNKNOWN" "$SPEED" "$AVG" "$ETA_TEXT"

    sleep 1

done

wait "$PID"
STATUS=$?
PID=""

if (( STATUS != 0 )); then
    echo
    echo "ERROR: DNS testing failed (exit code $STATUS)."
    exit 1
fi

# STEP 6: Final report

flock -s 9
read -r COMPLETED BYPASSED BLOCKED UNKNOWN < "$TMP/stats"
flock -u 9

ELAPSED=$((SECONDS - START))

AVG="$(awk -v t="$ELAPSED" -v n="$COMPLETED" \
    'BEGIN {if (n>0) printf "%.3f", t/n; else print "0"}')"

SPEED="$(awk -v n="$COMPLETED" -v t="$ELAPSED" \
    'BEGIN {if (t>0) printf "%.1f", n/t; else print "0"}')"

{
    echo '"Domain","Source File","A Record","AAAA Record"'
    cat "$TMP/resolved"
} > "$OUTPUT" || {
    echo "ERROR: CSV export failed."
    exit 1
}

echo
echo
echo "=============== FINAL REPORT ==============="
echo
echo "Total domains:       $TOTAL"
echo "Scanned:             $COMPLETED"
echo "Bypassed:            $BYPASSED"
echo "Confirmed blocked:   $BLOCKED"
echo "Unknown:             $UNKNOWN"
echo
echo "Total time:          $(format_time "$ELAPSED")"
echo "Average per domain:  $AVG seconds"
echo "Average speed:       $SPEED domains/sec"
echo "Parallel workers:    $WORKERS"
echo
echo "CSV results:         $OUTPUT"
echo
echo "============================================="
