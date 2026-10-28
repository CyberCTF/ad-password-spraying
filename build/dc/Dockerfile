# Samba, acting as an Active Directory Domain Controller, in a single Linux container.
# It provisions the realm SUMMIT.LAB at first start (idempotent), seeds a roster of store-staff
# domain users (one of which, k.verma, still uses the onboarding default password), disables
# account lockout, and plants the flag in a share only k.verma may read. The spray client
# tooling (MIT Kerberos + smbclient) ships in the image so the lab's check can prove the path
# from inside the DC with the same native tools a student would point at it from an attack box.
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

# Preseed krb5 so its package install never prompts.
RUN set -eux; \
    echo "krb5-config krb5-config/default_realm string SUMMIT.LAB" | debconf-set-selections; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        samba samba-ad-provision samba-dsdb-modules samba-vfs-modules smbclient ldb-tools \
        winbind libnss-winbind libpam-winbind \
        krb5-user krb5-config ldap-utils \
        dnsutils procps iproute2 ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    # The AD DC runs as the single `samba` process, never the standalone smbd/nmbd/winbind
    # units, so make sure none of those can start on their own.
    rm -f /etc/samba/smb.conf

COPY share.conf    /opt/pwspray/share.conf
COPY wordlist.txt  /opt/pwspray/wordlist.txt
COPY users.txt     /opt/pwspray/users.txt
COPY check.sh      /opt/pwspray/check.sh
COPY entrypoint.sh /opt/pwspray/entrypoint.sh
RUN chmod +x /opt/pwspray/entrypoint.sh /opt/pwspray/check.sh

# AD/Kerberos surface.
EXPOSE 53/tcp 53/udp 88/tcp 88/udp 389/tcp 445/tcp 464/tcp 464/udp 636/tcp 3268/tcp

CMD ["/opt/pwspray/entrypoint.sh"]
