#!/bin/bash
# Brings the Samba AD DC up deterministically and idempotently:
#   1. provisions realm SUMMIT.LAB once (skipped on restart),
#   2. seeds a roster of store-staff domain users -- all with policy-compliant passwords, but
#      exactly one (k.verma) still uses the weak onboarding default that store staff are handed,
#      while the rest are strong and random -- and disables account lockout so password spraying
#      is viable,
#   3. plants the flag in a share only k.verma may read,
#   4. runs the single `samba` AD DC process in the foreground.
# Re-running it against an already-provisioned DC changes nothing (safe restart).
#
# Scenario: Summit Retail Group, a retail chain. Onboarding hands every new store employee the
# same default password (Summer2024), and many never change it; k.verma (a store manager) is the
# account that still uses it.
set -euo pipefail

REALM="SUMMIT.LAB"
DOMAIN="SUMMIT"
# DC administrator password: infrastructure only, never shown to the student.
ADMIN_PASS="DCAdm1n#Summit2024"

# The sprayable account: policy-compliant (upper+lower+digits, length 10) but the weak onboarding
# default any spray wordlist carries. This is the single account the student recovers.
SPRAY_USER="k.verma"
SPRAY_PASS="Summer2024"

# The domain roster. Every account other than SPRAY_USER carries a long, random, policy-compliant
# password that no spray wordlist will ever hit -- they are the negative control. Only k.verma
# reuses the weak onboarding default.
declare -a ACCOUNTS=(
  "m.oulton:Gh7xPq2mWz9R@k"
  "s.datta:Vt4nLb8sYc3H#d"
  "r.novak:Qm9zXr5kPw2N%f"
  "t.bako:Lp2wKd7vBt6C-j"
  "e.schmidt:Rf8yHn3qMx4Z_s"
  "l.moreau:Dw5cJt9bVl2P+k"
  "d.nguyen:Nk3gRq7xWm8Y=d"
  "k.verma:Summer2024"
  "a.kowalski:Zb6pTf4nQc9H@s"
  "p.ellison:Ht2mXv8kLr5W#d"
  "j.ferreira:Cj9sNb3yPq6Z%x"
  "c.okafor:Wd4vKt7mHc2R-n"
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
printf 'nameserver 127.0.0.1\nsearch summit.lab\n' > /etc/resolv.conf 2>/dev/null || true
grep -q 'dc.summit.lab' /etc/hosts 2>/dev/null || \
  printf '127.0.0.1 dc.summit.lab dc\n' >> /etc/hosts 2>/dev/null || true

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
mkdir -p /srv/storeops
if [ -s /ctf/flag ]; then
  cp -f /ctf/flag /srv/storeops/flag.txt
else
  printf 'FLAG{dev-pwspray-summit}\n' > /srv/storeops/flag.txt
fi
chmod 0444 /srv/storeops/flag.txt

log "starting samba (AD DC) ..."
exec samba --interactive --no-process-group
