#!/bin/bash
# =============================================================
# password_audit_v2.sh  -  Password & User Account Auditor (Member 2)
# Checks: UID 0 accounts, empty passwords, password expiry,
#         non-expiring passwords, old password-change dates.
# Commands used: grep, awk, cut, chage
#
# TEAM OUTPUT FORMAT (one finding per line, written to a file):
#   SEVERITY|ISSUE|RESOURCE|RECOMMENDATION
# Example:
#   CRITICAL|Empty password|testuser|Set a strong password or lock the account
#
# Usage: sudo ./password_audit_v2.sh [output_file]
#   default output file: password_findings.txt
# =============================================================

PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"
MAX_AGE_DAYS=90                              # older than this = "old"
OUT_FILE="${1:-password_findings.txt}"       # machine-readable findings

ISSUES=0

# report SEVERITY "ISSUE" "RESOURCE" "RECOMMENDATION"
report() {
    echo "[$1] $2: $3"                       # readable line on screen
    echo "$1|$2|$3|$4" >> "$OUT_FILE"        # team format line in file
    ISSUES=$((ISSUES + 1))
}

# Real login accounts: have a valid shell (not nologin/false)
login_users() {
    awk -F: '$7 !~ /(nologin|false)$/ && $7 != "" {print $1}' "$PASSWD_FILE"
}

echo "=============================================="
echo "      PASSWORD & USER ACCOUNT AUDIT"
echo "      $(date '+%Y-%m-%d %H:%M:%S')"
echo "=============================================="

# Shadow file needs root
if [ ! -r "$SHADOW_FILE" ]; then
    echo "[ERROR] Cannot read $SHADOW_FILE. Run with sudo."
    exit 1
fi

: > "$OUT_FILE"                              # start with an empty findings file

# ---------- 1. Multiple UID 0 accounts ----------
echo
echo "--- 1. Accounts with UID 0 ---"
UID0=$(awk -F: '$3 == 0 {print $1}' "$PASSWD_FILE")
FOUND=0
for u in $UID0; do
    if [ "$u" != "root" ]; then
        report CRITICAL "Non-root account with UID 0" "$u" \
               "Remove the account or change its UID"
        FOUND=1
    fi
done
[ "$FOUND" -eq 0 ] && echo "[OK] Only 'root' has UID 0"

# ---------- 2. Empty passwords ----------
echo
echo "--- 2. Empty password check ---"
EMPTY=$(awk -F: '$2 == "" {print $1}' "$SHADOW_FILE")
if [ -n "$EMPTY" ]; then
    for u in $EMPTY; do
        report CRITICAL "Empty password" "$u" \
               "Set a strong password or lock the account (passwd -l)"
    done
else
    echo "[OK] No accounts with empty passwords"
fi

# ---------- 3. Expiry / non-expiring / old password ----------
echo
echo "--- 3. Password expiry, non-expiring and old passwords ---"
TODAY=$(( $(date +%s) / 86400 ))
BEFORE=$ISSUES

for user in $(login_users); do
    # shadow fields: 2=hash 3=last change 5=max days
    LINE=$(grep "^${user}:" "$SHADOW_FILE")
    [ -z "$LINE" ] && continue
    HASH=$(echo "$LINE" | cut -d: -f2)
    LAST=$(echo "$LINE" | cut -d: -f3)
    MAXD=$(echo "$LINE" | cut -d: -f5)

    # Skip locked / no-password-login accounts (hash starts with ! or *)
    case "$HASH" in
        '!'*|'*'*) continue ;;
    esac

    # Non-expiring password
    if [ -z "$MAXD" ] || [ "$MAXD" -ge 99999 ] 2>/dev/null; then
        report MEDIUM "Non-expiring password" "$user" \
               "Set a maximum password age (chage -M 90 $user)"
    else
        # Already expired?
        if [ -n "$LAST" ] && [ $((LAST + MAXD)) -lt "$TODAY" ]; then
            report HIGH "Password has expired" "$user" \
                   "Ask the user to change the password (passwd $user)"
        fi
    fi

    # Old password-change date
    if [ -n "$LAST" ] && [ "$LAST" -gt 0 ]; then
        AGE=$((TODAY - LAST))
        if [ "$AGE" -gt "$MAX_AGE_DAYS" ]; then
            report MEDIUM "Password not changed for $AGE days" "$user" \
                   "Change the password; policy limit is $MAX_AGE_DAYS days"
        fi
    fi
done
[ "$ISSUES" -eq "$BEFORE" ] && echo "[OK] No expiry or password-age problems"

# ---------- 4. chage details (informational) ----------
echo
echo "--- 4. Password aging details (chage -l) ---"
for user in $(login_users); do
    echo ">> $user"
    chage -l "$user" 2>/dev/null | grep -E "Last password change|Password expires|Maximum number"
done

# ---------- Summary ----------
echo
echo "=============================================="
echo "Password audit finished. Issues found: $ISSUES"
echo "Findings saved to: $OUT_FILE"
echo "=============================================="
exit 0
