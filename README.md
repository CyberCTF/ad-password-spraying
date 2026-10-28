# Password Spraying (Active Directory)

A single-container Active Directory lab built with [Isoloom](https://www.isoloom.com):
[`isoloom.yml`](isoloom.yml) describes one Samba Domain Controller for the realm
**SUMMIT.LAB** (Summit Retail Group, a retail chain) — no Windows VMs. It seeds a roster of
store-staff domain users and disables account lockout. Every password satisfies the policy, but
exactly one account (`k.verma`, a store manager) still uses the weak onboarding default
(`Summer2024`); the rest are strong and random. The flag lives in a `storeops` share that only
`k.verma` may read.

| Machine | Service |
| --- | --- |
| dc | Samba AD DC: DNS 53, Kerberos 88, LDAP 389/636, SMB 445, kpasswd 464, GC 3268 |

## The attack

1. Take the user roster (given below, or enumerate it over null/low-priv LDAP on 389):
   `m.oulton, s.datta, r.novak, t.bako, e.schmidt, l.moreau, d.nguyen, k.verma, a.kowalski,
   p.ellison, j.ferreira, c.okafor`.
2. Spray a short list of common candidates (`Spring2024`, `Summer2024`, `Autumn2024`,
   `Winter2023`, …) across the whole roster — one password at a time, every user — from the
   attack box. Lockout is off, so it is safe:
   `nxc smb <dc> -u users.txt -p 'Summer2024' --continue-on-success` (or `kerbrute passwordspray`).
3. Exactly one account authenticates: `k.verma` / `Summer2024`.
4. Read the flag with it: `smbclient //dc/storeops -U 'SUMMIT\k.verma%Summer2024' -c 'get flag.txt'`.

## Run it

```bash
isoloom generate
isothrum up . --target docker
isothrum check . --target docker
isothrum down . --target docker
```

The same spec also runs on a local VM, a cloud VM, or Kubernetes targets that Isoloom supports.
This environment is deliberately vulnerable: keep it isolated.
