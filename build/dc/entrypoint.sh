#!/bin/bash
# Brings the Samba AD DC up deterministically and idempotently:
#   1. provisions realm NORTH.SEVENKINGDOMS.LOCAL once (skipped on restart),
#   2. seeds a themed set of domain users -- all with policy-compliant passwords, but exactly
#      one (samwell.tarly) uses a weak, guessable, seasonal word while the rest are strong and
#      random -- and disables account lockout so password spraying is viable,
#   3. plants the flag in a share only samwell.tarly may read,
#   4. runs the single `samba` AD DC process in the foreground.
# Re-running it against an already-provisioned DC changes nothing (safe restart).
set -euo pipefail

REALM="NORTH.SEVENKINGDOMS.LOCAL"
DOMAIN="NORTH"
# DC administrator password: infrastructure only, never shown to the student.
ADMIN_PASS="DCAdm1n#Winterfell2024"

# The sprayable account: policy-compliant (upper+lower+digits, length 10) but a weak, seasonal
# word any spray wordlist carries. This is the single account the student recovers.
SPRAY_USER="samwell.tarly"
SPRAY_PASS="Autumn2024"

# The domain roster. Every account below SPRAY_USER carries a long, random, policy-compliant
# password that no seasonal wordlist will ever hit -- they are the negative control. Only
# samwell.tarly reuses a weak seasonal password.
declare -a ACCOUNTS=(
  "eddard.stark:Gh7xPq2mWz9R@k"
  "catelyn.stark:Vt4nLb8sYc3H#d"
  "robb.stark:Qm9zXr5kPw2N%f"
  "sansa.stark:Lp2wKd7vBt6C-j"
  "arya.stark:Rf8yHn3qMx4Z_s"
  "brandon.stark:Dw5cJt9bVl2P+k"
  "jon.snow:Nk3gRq7xWm8Y=d"
  "samwell.tarly:Autumn2024"
  "jeor.mormont:Zb6pTf4nQc9H@s"
  "benjen.stark:Ht2mXv8kLr5W#d"
  "theon.greyjoy:Cj9sNb3yPq6Z%x"
  "maester.luwin:Wd4vKt7mHc2R-n"
)

PRIVATE_DIR="/var/lib/samba/private"
STAMP="${PRIVATE_DIR}/.isoloom-provisioned"

log() { echo "[dc] $*" >&2; }

if [ ! -f "${STAMP}" ]; then
  log "provisioning ${REALM} ..."
  rm -f /etc/samba/smb.conf
  # posix:eadb keeps NT ACLs in a tdb instead of security.* xattrs, so provisioning and the
  # file server work in an unprivileged container (no CAP_SYS_ADMIN). "ldap server require
  # strong auth = no" lets the student enumerate the roster over plain LDAP from the attack box.
  # Both --options persist into the generated smb.conf, so the running daemon uses them too.
  samba-tool domain provision \
    --use-rfc2307 \
    --realm="${REALM}" \
    --domain="${DOMAIN}" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --host-name=dc \
    --adminpass="${ADMIN_PASS}" \
    --option="posix:eadb=/var/lib/samba/eadb.tdb" \
    --option="ldap server require strong auth = no" >/dev/null

  # Kerberos client config and resolver point the DC at its own internal DNS.
  cp -f "${PRIVATE_DIR}/krb5.conf" /etc/krb5.conf

  # Publish the share that guards the flag.
  cat /opt/pwspray/share.conf >> /etc/samba/smb.conf

  touch "${STAMP}"
  log "provisioning done."
else
  log "already provisioned; reusing ${PRIVATE_DIR}."
fi

# Resolver: the DC resolves its own realm through Samba's internal DNS.
printf 'nameserver 127.0.0.1\nsearch north.sevenkingdoms.local\n' > /etc/resolv.conf 2>/dev/null || true
grep -q 'dc.north.sevenkingdoms.local' /etc/hosts 2>/dev/null || \
  printf '127.0.0.1 dc.north.sevenkingdoms.local dc\n' >> /etc/hosts 2>/dev/null || true

# The deliberate misconfiguration that makes spraying safe for an attacker: account lockout is
# turned off, so a candidate password can be tried against every user with no risk of locking
# anyone out. Idempotent -- re-applying the same value is a no-op.
samba-tool domain passwordsettings set --account-lockout-threshold=0 >/dev/null 2>&1 || true

# Seed the roster. Users are created offline against the local sam.ldb, so this works whether or
# not the samba process is already running. Passwords never expire, so the lab behaves the same
# on day 1 and day 60.
existing="$(samba-tool user list 2>/dev/null || true)"
for entry in "${ACCOUNTS[@]}"; do
  user="${entry%%:*}"
  pass="${entry#*:}"
  if ! printf '%s\n' "${existing}" | grep -qx "${user}"; then
    log "creating user ${user}"
    samba-tool user create "${user}" "${pass}" >/dev/null
  fi
  samba-tool user setexpiry "${user}" --noexpiry >/dev/null 2>&1 || true
done

# Plant the flag inside the share. CTF_FLAG_MAIN is delivered by the launcher at /ctf/flag
# (Isoloom's sensitive-input-as-file mechanism); fall back to a dev flag for a bare run.
mkdir -p /srv/nightswatch
if [ -s /ctf/flag ]; then
  cp -f /ctf/flag /srv/nightswatch/flag.txt
else
  printf 'FLAG{dev-pwspray-north-samwell.tarly}\n' > /srv/nightswatch/flag.txt
fi
chmod 0444 /srv/nightswatch/flag.txt

log "starting samba (AD DC) ..."
exec samba --interactive --no-process-group
