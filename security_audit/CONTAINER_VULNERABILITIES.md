# Container vulnerability inventory — baseline and final

Final application scan: 2026-10-12T11:00:41.885720668Z; Trivy 0.75.0; Linux arm64. Local image ID `sha256:ebbbdac9dc17f6b2eec57214dc05e4d93477b247a4479b6ffb9adc7624ea35aa`. This is not a registry manifest digest. Full raw reports retain vendor scores/descriptions/references; image/runtime metadata and SBOM are saved separately.

## Final counts

| Image / target | Critical | High | Medium | Low | Unknown | Secret alerts |
| --- | --- | --- | --- | --- | --- | --- |
| App / /audit/final.tar (debian 13.7) | 0 | 44 | 58 | 61 | 1 | 0 |
| App / Python | 0 | 0 | 0 | 0 | 0 | 0 |
| Hardened postgres | 0 | 0 | 0 | 0 | 0 | 0 |
| Hardened redis | 0 | 0 | 0 | 0 | 0 | 0 |

The final application has **164 package entries across 71 distinct IDs**: 44 HIGH, 58 MEDIUM, 61 LOW and one UNKNOWN. All are OS package matches; no Python package findings or app-image secret alerts remain. Repeat binary-package matches do not represent 44 distinct remotely exploitable flaws. The scan lists no fixed package version for these remaining release-specific entries. Counts reflect this scanner database and image, not unknown vulnerabilities.

## Implemented image fixes

- Removed base pip and ensurepip from the final runtime filesystem, eliminating all six installer findings; verified both base and venv locations.
- Installed signed Debian `liblzma5=5.8.1-1+deb13u2`, eliminating the two fixable UNKNOWN entries. The primary [Debian advisory](https://security-tracker.debian.org/tracker/DSA-6549-1) identifies this fixed release.
- Derived PostgreSQL removes unused `gosu`, avoiding its embedded Go-stdlib findings under the enforced non-root startup. Both stores receive signed Alpine `zlib=1.3.2-r1`; Redis also pins fixed OpenSSL libraries `3.3.7-r2`. The final scans report zero datastore vulnerability entries.
- Full all-severity reports/SBOM are retained; CI gates every unreviewed HIGH/CRITICAL rather than hiding unfixed packages.

## HIGH workload assessments

Exact ID/package/version assessments are in [container-risk-exceptions.json](container-risk-exceptions.json), expiring **2026-11-10**. These assess the inspected non-root/read-only/capability-free/no-privilege-escalation service, not the packages in every possible use. A new version, expired assessment, new HIGH/CRITICAL or changed reachable feature requires review. The application does not invoke mount/nsenter/ACL/terminfo tools or Perl archives. `systemd-homed` and Perl `Archive::Tar` were absent on image inspection.

| CVE | Source feature / precondition | Workload reasoning | Vendor record |
| --- | --- | --- | --- |
| CVE-2026-76642 | Privileged mount helper failure hooks | No mount calls; ALL capabilities dropped and no privilege escalation. | [Debian](https://security-tracker.debian.org/tracker/CVE-2026-76642) |
| CVE-2026-78408 | Privileged nsenter cgroup/descriptor behavior | No namespace-entry calls or relevant privileges. | [Debian](https://security-tracker.debian.org/tracker/CVE-2026-78408) |
| CVE-2026-78409 | Detached-tree/subdirectory mount handling | No mount operation or attacker-selected mount input. | [Debian](https://security-tracker.debian.org/tracker/CVE-2026-78409) |
| CVE-2026-78410 | Restricted bind-mount ownership handling | No bind mounts from application routes or relevant privileges. | [Debian](https://security-tracker.debian.org/tracker/CVE-2026-78410) |
| CVE-2026-54369 | Privileged ACL path handling | No attacker-selected privileged ACL calls or ACL utility route. | [Debian](https://security-tracker.debian.org/tracker/CVE-2026-54369) |
| CVE-2025-69720 | infocmp parsing overflow | Installed utility never called by headless service; no terminal/terminfo input path. | [Debian](https://security-tracker.debian.org/tracker/CVE-2025-69720) |
| CVE-2026-16742 | systemd-homed identity handling | Vulnerable feature/binary absent; library/source-package matches retained. | [Debian](https://security-tracker.debian.org/tracker/CVE-2026-16742) |
| CVE-2026-9538 | Perl Archive::Tar memory exhaustion | Archive::Tar module absent; app does not execute Perl/extract archives. | [Debian](https://security-tracker.debian.org/tracker/CVE-2026-9538) |

These conditions do not classify every remaining MEDIUM/LOW/UNKNOWN entry as non-affected. Their complete inventory remains below. Existing code/transport/resource controls and current vendor status must be reconsidered on release changes. No blanket waiver is used.

## Every final application entry

| ID | Package | Installed version | Fixed version in scan | Severity | Vendor status |
| --- | --- | --- | --- | --- | --- |
| [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | libncursesw6 | 6.5+20250216-2 | not listed | HIGH | affected |
| [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | libtinfo6 | 6.5+20250216-2 | not listed | HIGH | affected |
| [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | ncurses-base | 6.5+20250216-2 | not listed | HIGH | affected |
| [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | ncurses-bin | 6.5+20250216-2 | not listed | HIGH | affected |
| [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742) | libsystemd0 | 257.13-1~deb13u1 | not listed | HIGH | affected |
| [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742) | libudev1 | 257.13-1~deb13u1 | not listed | HIGH | affected |
| [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369) | libacl1 | 2.3.2-2+b1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | bsdutils | 1:2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | libblkid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | liblastlog2-2 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | libmount1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | libsmartcols1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | libuuid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | login | 1:4.16.0-2+really2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | mount | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | util-linux | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | bsdutils | 1:2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | libblkid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | liblastlog2-2 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | libmount1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | libsmartcols1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | libuuid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | login | 1:4.16.0-2+really2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | mount | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | util-linux | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | bsdutils | 1:2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | libblkid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | liblastlog2-2 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | libmount1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | libsmartcols1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | libuuid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | login | 1:4.16.0-2+really2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | mount | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | util-linux | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | bsdutils | 1:2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | libblkid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | liblastlog2-2 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | libmount1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | libsmartcols1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | libuuid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | login | 1:4.16.0-2+really2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | mount | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | util-linux | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) | perl-base | 5.40.1-6+deb13u1 | not listed | HIGH | fix_deferred |
| [CVE-2005-2541](https://security-tracker.debian.org/tracker/CVE-2005-2541) | tar | 1.35+dfsg-3.1 | not listed | LOW | affected |
| [CVE-2007-5686](https://security-tracker.debian.org/tracker/CVE-2007-5686) | login.defs | 1:4.17.4-2 | not listed | LOW | affected |
| [CVE-2007-5686](https://security-tracker.debian.org/tracker/CVE-2007-5686) | passwd | 1:4.17.4-2 | not listed | LOW | affected |
| [CVE-2010-4756](https://security-tracker.debian.org/tracker/CVE-2010-4756) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2010-4756](https://security-tracker.debian.org/tracker/CVE-2010-4756) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2011-3374](https://security-tracker.debian.org/tracker/CVE-2011-3374) | apt | 3.0.3 | not listed | LOW | affected |
| [CVE-2011-3374](https://security-tracker.debian.org/tracker/CVE-2011-3374) | libapt-pkg7.0 | 3.0.3 | not listed | LOW | affected |
| [CVE-2011-4116](https://security-tracker.debian.org/tracker/CVE-2011-4116) | perl-base | 5.40.1-6+deb13u1 | not listed | LOW | affected |
| [CVE-2013-4392](https://security-tracker.debian.org/tracker/CVE-2013-4392) | libsystemd0 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2013-4392](https://security-tracker.debian.org/tracker/CVE-2013-4392) | libudev1 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2017-18018](https://security-tracker.debian.org/tracker/CVE-2017-18018) | coreutils | 9.7-3 | not listed | LOW | affected |
| [CVE-2018-20796](https://security-tracker.debian.org/tracker/CVE-2018-20796) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2018-20796](https://security-tracker.debian.org/tracker/CVE-2018-20796) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010022](https://security-tracker.debian.org/tracker/CVE-2019-1010022) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010022](https://security-tracker.debian.org/tracker/CVE-2019-1010022) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010023](https://security-tracker.debian.org/tracker/CVE-2019-1010023) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010023](https://security-tracker.debian.org/tracker/CVE-2019-1010023) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010024](https://security-tracker.debian.org/tracker/CVE-2019-1010024) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010024](https://security-tracker.debian.org/tracker/CVE-2019-1010024) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010025](https://security-tracker.debian.org/tracker/CVE-2019-1010025) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010025](https://security-tracker.debian.org/tracker/CVE-2019-1010025) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-9192](https://security-tracker.debian.org/tracker/CVE-2019-9192) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-9192](https://security-tracker.debian.org/tracker/CVE-2019-9192) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2021-45346](https://security-tracker.debian.org/tracker/CVE-2021-45346) | libsqlite3-0 | 3.46.1-7+deb13u2 | not listed | LOW | affected |
| [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | bsdutils | 1:2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | libblkid1 | 2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | liblastlog2-2 | 2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | libmount1 | 2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | libsmartcols1 | 2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | libuuid1 | 2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | login | 1:4.16.0-2+really2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | mount | 2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563) | util-linux | 2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2023-31437](https://security-tracker.debian.org/tracker/CVE-2023-31437) | libsystemd0 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2023-31437](https://security-tracker.debian.org/tracker/CVE-2023-31437) | libudev1 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2023-31438](https://security-tracker.debian.org/tracker/CVE-2023-31438) | libsystemd0 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2023-31438](https://security-tracker.debian.org/tracker/CVE-2023-31438) | libudev1 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2023-31439](https://security-tracker.debian.org/tracker/CVE-2023-31439) | libsystemd0 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2023-31439](https://security-tracker.debian.org/tracker/CVE-2023-31439) | libudev1 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2024-56433](https://security-tracker.debian.org/tracker/CVE-2024-56433) | login.defs | 1:4.17.4-2 | not listed | LOW | affected |
| [CVE-2024-56433](https://security-tracker.debian.org/tracker/CVE-2024-56433) | passwd | 1:4.17.4-2 | not listed | LOW | affected |
| [CVE-2025-5278](https://security-tracker.debian.org/tracker/CVE-2025-5278) | coreutils | 9.7-3 | not listed | LOW | affected |
| [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141) | libncursesw6 | 6.5+20250216-2 | not listed | LOW | affected |
| [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141) | libtinfo6 | 6.5+20250216-2 | not listed | LOW | affected |
| [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141) | ncurses-base | 6.5+20250216-2 | not listed | LOW | affected |
| [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141) | ncurses-bin | 6.5+20250216-2 | not listed | LOW | affected |
| [CVE-2025-70873](https://security-tracker.debian.org/tracker/CVE-2025-70873) | libsqlite3-0 | 3.46.1-7+deb13u2 | not listed | LOW | affected |
| [CVE-2026-102473](https://security-tracker.debian.org/tracker/CVE-2026-102473) | dash | 0.5.12-12 | not listed | LOW | affected |
| [CVE-2026-102474](https://security-tracker.debian.org/tracker/CVE-2026-102474) | dash | 0.5.12-12 | not listed | LOW | affected |
| [CVE-2026-40228](https://security-tracker.debian.org/tracker/CVE-2026-40228) | libsystemd0 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2026-40228](https://security-tracker.debian.org/tracker/CVE-2026-40228) | libudev1 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2026-53910](https://security-tracker.debian.org/tracker/CVE-2026-53910) | diffutils | 1:3.10-4 | not listed | LOW | affected |
| [CVE-2026-56391](https://security-tracker.debian.org/tracker/CVE-2026-56391) | coreutils | 9.7-3 | not listed | LOW | affected |
| [CVE-2026-56392](https://security-tracker.debian.org/tracker/CVE-2026-56392) | coreutils | 9.7-3 | not listed | LOW | affected |
| [CVE-2026-97399](https://security-tracker.debian.org/tracker/CVE-2026-97399) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2026-97399](https://security-tracker.debian.org/tracker/CVE-2026-97399) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [TEMP-0290435-0B57B5](https://security-tracker.debian.org/tracker/TEMP-0290435-0B57B5) | tar | 1.35+dfsg-3.1 | not listed | LOW | affected |
| [TEMP-0517018-A83CE6](https://security-tracker.debian.org/tracker/TEMP-0517018-A83CE6) | sysvinit-utils | 3.14-4 | not listed | LOW | affected |
| [TEMP-0628843-DBAD28](https://security-tracker.debian.org/tracker/TEMP-0628843-DBAD28) | login.defs | 1:4.17.4-2 | not listed | LOW | affected |
| [TEMP-0628843-DBAD28](https://security-tracker.debian.org/tracker/TEMP-0628843-DBAD28) | passwd | 1:4.17.4-2 | not listed | LOW | affected |
| [TEMP-0841856-B18BAF](https://security-tracker.debian.org/tracker/TEMP-0841856-B18BAF) | bash | 5.2.37-2+b10 | not listed | LOW | affected |
| [CVE-2026-102010](https://security-tracker.debian.org/tracker/CVE-2026-102010) | gcc-14-base | 14.2.0-19 | not listed | MEDIUM | affected |
| [CVE-2026-102010](https://security-tracker.debian.org/tracker/CVE-2026-102010) | libgcc-s1 | 14.2.0-19 | not listed | MEDIUM | affected |
| [CVE-2026-102010](https://security-tracker.debian.org/tracker/CVE-2026-102010) | libstdc++6 | 14.2.0-19 | not listed | MEDIUM | affected |
| [CVE-2026-15059](https://security-tracker.debian.org/tracker/CVE-2026-15059) | libsystemd0 | 257.13-1~deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-15059](https://security-tracker.debian.org/tracker/CVE-2026-15059) | libudev1 | 257.13-1~deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-15534](https://security-tracker.debian.org/tracker/CVE-2026-15534) | perl-base | 5.40.1-6+deb13u1 | not listed | MEDIUM | fix_deferred |
| [CVE-2026-18374](https://security-tracker.debian.org/tracker/CVE-2026-18374) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-18374](https://security-tracker.debian.org/tracker/CVE-2026-18374) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-18477](https://security-tracker.debian.org/tracker/CVE-2026-18477) | tar | 1.35+dfsg-3.1 | not listed | MEDIUM | affected |
| [CVE-2026-18508](https://security-tracker.debian.org/tracker/CVE-2026-18508) | tar | 1.35+dfsg-3.1 | not listed | MEDIUM | affected |
| [CVE-2026-19499](https://security-tracker.debian.org/tracker/CVE-2026-19499) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-19499](https://security-tracker.debian.org/tracker/CVE-2026-19499) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-19542](https://security-tracker.debian.org/tracker/CVE-2026-19542) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-19542](https://security-tracker.debian.org/tracker/CVE-2026-19542) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-27171](https://security-tracker.debian.org/tracker/CVE-2026-27171) | zlib1g | 1:1.3.dfsg+really1.3.1-1+b1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | bsdutils | 1:2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | libblkid1 | 2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | liblastlog2-2 | 2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | libmount1 | 2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | libsmartcols1 | 2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | libuuid1 | 2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | login | 1:4.16.0-2+really2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | mount | 2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184) | util-linux | 2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-42250](https://security-tracker.debian.org/tracker/CVE-2026-42250) | libbz2-1.0 | 1.0.8-6 | not listed | MEDIUM | affected |
| [CVE-2026-50812](https://security-tracker.debian.org/tracker/CVE-2026-50812) | libsqlite3-0 | 3.46.1-7+deb13u2 | not listed | MEDIUM | affected |
| [CVE-2026-50813](https://security-tracker.debian.org/tracker/CVE-2026-50813) | libsqlite3-0 | 3.46.1-7+deb13u2 | not listed | MEDIUM | affected |
| [CVE-2026-5435](https://security-tracker.debian.org/tracker/CVE-2026-5435) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-5435](https://security-tracker.debian.org/tracker/CVE-2026-5435) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-54370](https://security-tracker.debian.org/tracker/CVE-2026-54370) | libacl1 | 2.3.2-2+b1 | not listed | MEDIUM | affected |
| [CVE-2026-54371](https://security-tracker.debian.org/tracker/CVE-2026-54371) | libattr1 | 1:2.5.2-3 | not listed | MEDIUM | affected |
| [CVE-2026-54411](https://security-tracker.debian.org/tracker/CVE-2026-54411) | libpam-modules | 1.7.0-5 | not listed | MEDIUM | affected |
| [CVE-2026-54411](https://security-tracker.debian.org/tracker/CVE-2026-54411) | libpam-modules-bin | 1.7.0-5 | not listed | MEDIUM | affected |
| [CVE-2026-54411](https://security-tracker.debian.org/tracker/CVE-2026-54411) | libpam-runtime | 1.7.0-5 | not listed | MEDIUM | affected |
| [CVE-2026-54411](https://security-tracker.debian.org/tracker/CVE-2026-54411) | libpam0g | 1.7.0-5 | not listed | MEDIUM | affected |
| [CVE-2026-5704](https://security-tracker.debian.org/tracker/CVE-2026-5704) | tar | 1.35+dfsg-3.1 | not listed | MEDIUM | affected |
| [CVE-2026-6238](https://security-tracker.debian.org/tracker/CVE-2026-6238) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-6238](https://security-tracker.debian.org/tracker/CVE-2026-6238) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-6368](https://security-tracker.debian.org/tracker/CVE-2026-6368) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-6368](https://security-tracker.debian.org/tracker/CVE-2026-6368) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-6791](https://security-tracker.debian.org/tracker/CVE-2026-6791) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-6791](https://security-tracker.debian.org/tracker/CVE-2026-6791) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-77117](https://security-tracker.debian.org/tracker/CVE-2026-77117) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-77117](https://security-tracker.debian.org/tracker/CVE-2026-77117) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-80489](https://security-tracker.debian.org/tracker/CVE-2026-80489) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-80489](https://security-tracker.debian.org/tracker/CVE-2026-80489) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-85091](https://security-tracker.debian.org/tracker/CVE-2026-85091) | zlib1g | 1:1.3.dfsg+really1.3.1-1+b1 | not listed | MEDIUM | affected |
| [CVE-2026-8674](https://security-tracker.debian.org/tracker/CVE-2026-8674) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-8674](https://security-tracker.debian.org/tracker/CVE-2026-8674) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-86805](https://security-tracker.debian.org/tracker/CVE-2026-86805) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-86805](https://security-tracker.debian.org/tracker/CVE-2026-86805) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-89092](https://security-tracker.debian.org/tracker/CVE-2026-89092) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-89092](https://security-tracker.debian.org/tracker/CVE-2026-89092) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-95619](https://security-tracker.debian.org/tracker/CVE-2026-95619) | gcc-14-base | 14.2.0-19 | not listed | MEDIUM | affected |
| [CVE-2026-95619](https://security-tracker.debian.org/tracker/CVE-2026-95619) | libgcc-s1 | 14.2.0-19 | not listed | MEDIUM | affected |
| [CVE-2026-95619](https://security-tracker.debian.org/tracker/CVE-2026-95619) | libstdc++6 | 14.2.0-19 | not listed | MEDIUM | affected |
| [CVE-2026-95818](https://security-tracker.debian.org/tracker/CVE-2026-95818) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-95818](https://security-tracker.debian.org/tracker/CVE-2026-95818) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-82560](https://security-tracker.debian.org/tracker/CVE-2026-82560) | perl-base | 5.40.1-6+deb13u1 | not listed | UNKNOWN | affected |

---

# Baseline container vulnerability inventory (2026-10-11)

Trivy 0.75.0 scanned the locally built Linux arm64 image at 2026-10-11T18:47:04.655754462Z. Image ID: `sha256:42cfa04bfc2a9a85058233edabafec1f854856493dce106697c4fe2f27e3ede0`. This is the exported local Docker image ID, not a registry manifest digest. Docker build reused cached layers matching the current Dockerfile and source.

The scan reported 172 package vulnerability entries covering 79 unique IDs. Entries repeat across binary packages from the same source package. Vendor severity does not establish runtime reachability. Full descriptions, package metadata, references and vendor scores are retained in evidence/trivy.json. No secret alerts were reported.

## Scan counts

| Target | Critical | High | Medium | Low | Unknown |
| --- | --- | --- | --- | --- | --- |
| /audit/image.tar (debian 13.7) | 0 | 44 | 58 | 61 | 3 |
| Python | 0 | 0 | 5 | 1 | 0 |

## All reported vulnerability entries

Empty fixed-version fields mean this scanner lists no fixed package version for the identified release. Some upstream fixes exist in other releases; that is different from a fix in the selected Debian release. The report preserves scanner severity and does not assign identical application risk to every entry.

| ID | Package | Installed version | Fixed version | Severity | Status |
| --- | --- | --- | --- | --- | --- |
| [CVE-2025-69720](https://avd.aquasec.com/nvd/cve-2025-69720) | libncursesw6 | 6.5+20250216-2 | not listed | HIGH | affected |
| [CVE-2025-69720](https://avd.aquasec.com/nvd/cve-2025-69720) | libtinfo6 | 6.5+20250216-2 | not listed | HIGH | affected |
| [CVE-2025-69720](https://avd.aquasec.com/nvd/cve-2025-69720) | ncurses-base | 6.5+20250216-2 | not listed | HIGH | affected |
| [CVE-2025-69720](https://avd.aquasec.com/nvd/cve-2025-69720) | ncurses-bin | 6.5+20250216-2 | not listed | HIGH | affected |
| [CVE-2026-16742](https://avd.aquasec.com/nvd/cve-2026-16742) | libsystemd0 | 257.13-1~deb13u1 | not listed | HIGH | affected |
| [CVE-2026-16742](https://avd.aquasec.com/nvd/cve-2026-16742) | libudev1 | 257.13-1~deb13u1 | not listed | HIGH | affected |
| [CVE-2026-54369](https://avd.aquasec.com/nvd/cve-2026-54369) | libacl1 | 2.3.2-2+b1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642) | bsdutils | 1:2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642) | libblkid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642) | liblastlog2-2 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642) | libmount1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642) | libsmartcols1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642) | libuuid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642) | login | 1:4.16.0-2+really2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642) | mount | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642) | util-linux | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408) | bsdutils | 1:2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408) | libblkid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408) | liblastlog2-2 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408) | libmount1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408) | libsmartcols1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408) | libuuid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408) | login | 1:4.16.0-2+really2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408) | mount | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408) | util-linux | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409) | bsdutils | 1:2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409) | libblkid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409) | liblastlog2-2 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409) | libmount1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409) | libsmartcols1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409) | libuuid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409) | login | 1:4.16.0-2+really2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409) | mount | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409) | util-linux | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410) | bsdutils | 1:2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410) | libblkid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410) | liblastlog2-2 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410) | libmount1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410) | libsmartcols1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410) | libuuid1 | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410) | login | 1:4.16.0-2+really2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410) | mount | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410) | util-linux | 2.41.5-0+deb13u1 | not listed | HIGH | affected |
| [CVE-2026-9538](https://avd.aquasec.com/nvd/cve-2026-9538) | perl-base | 5.40.1-6+deb13u1 | not listed | HIGH | fix_deferred |
| [CVE-2025-8869](https://avd.aquasec.com/nvd/cve-2025-8869) | pip | 25.0.1 | 25.3 | MEDIUM | fixed |
| [CVE-2026-102010](https://avd.aquasec.com/nvd/cve-2026-102010) | gcc-14-base | 14.2.0-19 | not listed | MEDIUM | affected |
| [CVE-2026-102010](https://avd.aquasec.com/nvd/cve-2026-102010) | libgcc-s1 | 14.2.0-19 | not listed | MEDIUM | affected |
| [CVE-2026-102010](https://avd.aquasec.com/nvd/cve-2026-102010) | libstdc++6 | 14.2.0-19 | not listed | MEDIUM | affected |
| [CVE-2026-13346](https://avd.aquasec.com/nvd/cve-2026-13346) | pip | 25.0.1 | 26.2.0 | MEDIUM | fixed |
| [CVE-2026-15059](https://avd.aquasec.com/nvd/cve-2026-15059) | libsystemd0 | 257.13-1~deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-15059](https://avd.aquasec.com/nvd/cve-2026-15059) | libudev1 | 257.13-1~deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-15534](https://avd.aquasec.com/nvd/cve-2026-15534) | perl-base | 5.40.1-6+deb13u1 | not listed | MEDIUM | fix_deferred |
| [CVE-2026-18374](https://avd.aquasec.com/nvd/cve-2026-18374) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-18374](https://avd.aquasec.com/nvd/cve-2026-18374) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-18477](https://avd.aquasec.com/nvd/cve-2026-18477) | tar | 1.35+dfsg-3.1 | not listed | MEDIUM | affected |
| [CVE-2026-18508](https://avd.aquasec.com/nvd/cve-2026-18508) | tar | 1.35+dfsg-3.1 | not listed | MEDIUM | affected |
| [CVE-2026-19499](https://avd.aquasec.com/nvd/cve-2026-19499) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-19499](https://avd.aquasec.com/nvd/cve-2026-19499) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-19542](https://avd.aquasec.com/nvd/cve-2026-19542) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-19542](https://avd.aquasec.com/nvd/cve-2026-19542) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-27171](https://avd.aquasec.com/nvd/cve-2026-27171) | zlib1g | 1:1.3.dfsg+really1.3.1-1+b1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184) | bsdutils | 1:2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184) | libblkid1 | 2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184) | liblastlog2-2 | 2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184) | libmount1 | 2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184) | libsmartcols1 | 2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184) | libuuid1 | 2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184) | login | 1:4.16.0-2+really2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184) | mount | 2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184) | util-linux | 2.41.5-0+deb13u1 | not listed | MEDIUM | affected |
| [CVE-2026-3219](https://avd.aquasec.com/nvd/cve-2026-3219) | pip | 25.0.1 | 26.1 | MEDIUM | fixed |
| [CVE-2026-42250](https://avd.aquasec.com/nvd/cve-2026-42250) | libbz2-1.0 | 1.0.8-6 | not listed | MEDIUM | affected |
| [CVE-2026-50812](https://avd.aquasec.com/nvd/cve-2026-50812) | libsqlite3-0 | 3.46.1-7+deb13u2 | not listed | MEDIUM | affected |
| [CVE-2026-50813](https://avd.aquasec.com/nvd/cve-2026-50813) | libsqlite3-0 | 3.46.1-7+deb13u2 | not listed | MEDIUM | affected |
| [CVE-2026-5435](https://avd.aquasec.com/nvd/cve-2026-5435) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-5435](https://avd.aquasec.com/nvd/cve-2026-5435) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-54370](https://avd.aquasec.com/nvd/cve-2026-54370) | libacl1 | 2.3.2-2+b1 | not listed | MEDIUM | affected |
| [CVE-2026-54371](https://avd.aquasec.com/nvd/cve-2026-54371) | libattr1 | 1:2.5.2-3 | not listed | MEDIUM | affected |
| [CVE-2026-54411](https://avd.aquasec.com/nvd/cve-2026-54411) | libpam-modules | 1.7.0-5 | not listed | MEDIUM | affected |
| [CVE-2026-54411](https://avd.aquasec.com/nvd/cve-2026-54411) | libpam-modules-bin | 1.7.0-5 | not listed | MEDIUM | affected |
| [CVE-2026-54411](https://avd.aquasec.com/nvd/cve-2026-54411) | libpam-runtime | 1.7.0-5 | not listed | MEDIUM | affected |
| [CVE-2026-54411](https://avd.aquasec.com/nvd/cve-2026-54411) | libpam0g | 1.7.0-5 | not listed | MEDIUM | affected |
| [CVE-2026-5704](https://avd.aquasec.com/nvd/cve-2026-5704) | tar | 1.35+dfsg-3.1 | not listed | MEDIUM | affected |
| [CVE-2026-6238](https://avd.aquasec.com/nvd/cve-2026-6238) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-6238](https://avd.aquasec.com/nvd/cve-2026-6238) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-6357](https://avd.aquasec.com/nvd/cve-2026-6357) | pip | 25.0.1 | 26.1 | MEDIUM | fixed |
| [CVE-2026-6368](https://avd.aquasec.com/nvd/cve-2026-6368) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-6368](https://avd.aquasec.com/nvd/cve-2026-6368) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-6791](https://avd.aquasec.com/nvd/cve-2026-6791) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-6791](https://avd.aquasec.com/nvd/cve-2026-6791) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-77117](https://avd.aquasec.com/nvd/cve-2026-77117) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-77117](https://avd.aquasec.com/nvd/cve-2026-77117) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-80489](https://avd.aquasec.com/nvd/cve-2026-80489) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-80489](https://avd.aquasec.com/nvd/cve-2026-80489) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-85091](https://avd.aquasec.com/nvd/cve-2026-85091) | zlib1g | 1:1.3.dfsg+really1.3.1-1+b1 | not listed | MEDIUM | affected |
| [CVE-2026-8643](https://avd.aquasec.com/nvd/cve-2026-8643) | pip | 25.0.1 | 26.1.2 | MEDIUM | fixed |
| [CVE-2026-8674](https://avd.aquasec.com/nvd/cve-2026-8674) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-8674](https://avd.aquasec.com/nvd/cve-2026-8674) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-86805](https://avd.aquasec.com/nvd/cve-2026-86805) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-86805](https://avd.aquasec.com/nvd/cve-2026-86805) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-89092](https://avd.aquasec.com/nvd/cve-2026-89092) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-89092](https://avd.aquasec.com/nvd/cve-2026-89092) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-95619](https://avd.aquasec.com/nvd/cve-2026-95619) | gcc-14-base | 14.2.0-19 | not listed | MEDIUM | affected |
| [CVE-2026-95619](https://avd.aquasec.com/nvd/cve-2026-95619) | libgcc-s1 | 14.2.0-19 | not listed | MEDIUM | affected |
| [CVE-2026-95619](https://avd.aquasec.com/nvd/cve-2026-95619) | libstdc++6 | 14.2.0-19 | not listed | MEDIUM | affected |
| [CVE-2026-95818](https://avd.aquasec.com/nvd/cve-2026-95818) | libc-bin | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2026-95818](https://avd.aquasec.com/nvd/cve-2026-95818) | libc6 | 2.41-12+deb13u4 | not listed | MEDIUM | affected |
| [CVE-2005-2541](https://avd.aquasec.com/nvd/cve-2005-2541) | tar | 1.35+dfsg-3.1 | not listed | LOW | affected |
| [CVE-2007-5686](https://avd.aquasec.com/nvd/cve-2007-5686) | login.defs | 1:4.17.4-2 | not listed | LOW | affected |
| [CVE-2007-5686](https://avd.aquasec.com/nvd/cve-2007-5686) | passwd | 1:4.17.4-2 | not listed | LOW | affected |
| [CVE-2010-4756](https://avd.aquasec.com/nvd/cve-2010-4756) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2010-4756](https://avd.aquasec.com/nvd/cve-2010-4756) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2011-3374](https://avd.aquasec.com/nvd/cve-2011-3374) | apt | 3.0.3 | not listed | LOW | affected |
| [CVE-2011-3374](https://avd.aquasec.com/nvd/cve-2011-3374) | libapt-pkg7.0 | 3.0.3 | not listed | LOW | affected |
| [CVE-2011-4116](https://avd.aquasec.com/nvd/cve-2011-4116) | perl-base | 5.40.1-6+deb13u1 | not listed | LOW | affected |
| [CVE-2013-4392](https://avd.aquasec.com/nvd/cve-2013-4392) | libsystemd0 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2013-4392](https://avd.aquasec.com/nvd/cve-2013-4392) | libudev1 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2017-18018](https://avd.aquasec.com/nvd/cve-2017-18018) | coreutils | 9.7-3 | not listed | LOW | affected |
| [CVE-2018-20796](https://avd.aquasec.com/nvd/cve-2018-20796) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2018-20796](https://avd.aquasec.com/nvd/cve-2018-20796) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010022](https://avd.aquasec.com/nvd/cve-2019-1010022) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010022](https://avd.aquasec.com/nvd/cve-2019-1010022) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010023](https://avd.aquasec.com/nvd/cve-2019-1010023) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010023](https://avd.aquasec.com/nvd/cve-2019-1010023) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010024](https://avd.aquasec.com/nvd/cve-2019-1010024) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010024](https://avd.aquasec.com/nvd/cve-2019-1010024) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010025](https://avd.aquasec.com/nvd/cve-2019-1010025) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-1010025](https://avd.aquasec.com/nvd/cve-2019-1010025) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-9192](https://avd.aquasec.com/nvd/cve-2019-9192) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2019-9192](https://avd.aquasec.com/nvd/cve-2019-9192) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2021-45346](https://avd.aquasec.com/nvd/cve-2021-45346) | libsqlite3-0 | 3.46.1-7+deb13u2 | not listed | LOW | affected |
| [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563) | bsdutils | 1:2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563) | libblkid1 | 2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563) | liblastlog2-2 | 2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563) | libmount1 | 2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563) | libsmartcols1 | 2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563) | libuuid1 | 2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563) | login | 1:4.16.0-2+really2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563) | mount | 2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563) | util-linux | 2.41.5-0+deb13u1 | not listed | LOW | affected |
| [CVE-2023-31437](https://avd.aquasec.com/nvd/cve-2023-31437) | libsystemd0 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2023-31437](https://avd.aquasec.com/nvd/cve-2023-31437) | libudev1 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2023-31438](https://avd.aquasec.com/nvd/cve-2023-31438) | libsystemd0 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2023-31438](https://avd.aquasec.com/nvd/cve-2023-31438) | libudev1 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2023-31439](https://avd.aquasec.com/nvd/cve-2023-31439) | libsystemd0 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2023-31439](https://avd.aquasec.com/nvd/cve-2023-31439) | libudev1 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2024-56433](https://avd.aquasec.com/nvd/cve-2024-56433) | login.defs | 1:4.17.4-2 | not listed | LOW | affected |
| [CVE-2024-56433](https://avd.aquasec.com/nvd/cve-2024-56433) | passwd | 1:4.17.4-2 | not listed | LOW | affected |
| [CVE-2025-5278](https://avd.aquasec.com/nvd/cve-2025-5278) | coreutils | 9.7-3 | not listed | LOW | affected |
| [CVE-2025-6141](https://avd.aquasec.com/nvd/cve-2025-6141) | libncursesw6 | 6.5+20250216-2 | not listed | LOW | affected |
| [CVE-2025-6141](https://avd.aquasec.com/nvd/cve-2025-6141) | libtinfo6 | 6.5+20250216-2 | not listed | LOW | affected |
| [CVE-2025-6141](https://avd.aquasec.com/nvd/cve-2025-6141) | ncurses-base | 6.5+20250216-2 | not listed | LOW | affected |
| [CVE-2025-6141](https://avd.aquasec.com/nvd/cve-2025-6141) | ncurses-bin | 6.5+20250216-2 | not listed | LOW | affected |
| [CVE-2025-70873](https://avd.aquasec.com/nvd/cve-2025-70873) | libsqlite3-0 | 3.46.1-7+deb13u2 | not listed | LOW | affected |
| [CVE-2026-102473](https://avd.aquasec.com/nvd/cve-2026-102473) | dash | 0.5.12-12 | not listed | LOW | affected |
| [CVE-2026-102474](https://avd.aquasec.com/nvd/cve-2026-102474) | dash | 0.5.12-12 | not listed | LOW | affected |
| [CVE-2026-1703](https://avd.aquasec.com/nvd/cve-2026-1703) | pip | 25.0.1 | 26.0 | LOW | fixed |
| [CVE-2026-40228](https://avd.aquasec.com/nvd/cve-2026-40228) | libsystemd0 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2026-40228](https://avd.aquasec.com/nvd/cve-2026-40228) | libudev1 | 257.13-1~deb13u1 | not listed | LOW | affected |
| [CVE-2026-53910](https://avd.aquasec.com/nvd/cve-2026-53910) | diffutils | 1:3.10-4 | not listed | LOW | affected |
| [CVE-2026-56391](https://avd.aquasec.com/nvd/cve-2026-56391) | coreutils | 9.7-3 | not listed | LOW | affected |
| [CVE-2026-56392](https://avd.aquasec.com/nvd/cve-2026-56392) | coreutils | 9.7-3 | not listed | LOW | affected |
| [CVE-2026-97399](https://avd.aquasec.com/nvd/cve-2026-97399) | libc-bin | 2.41-12+deb13u4 | not listed | LOW | affected |
| [CVE-2026-97399](https://avd.aquasec.com/nvd/cve-2026-97399) | libc6 | 2.41-12+deb13u4 | not listed | LOW | affected |
| [TEMP-0290435-0B57B5](https://security-tracker.debian.org/tracker/TEMP-0290435-0B57B5) | tar | 1.35+dfsg-3.1 | not listed | LOW | affected |
| [TEMP-0517018-A83CE6](https://security-tracker.debian.org/tracker/TEMP-0517018-A83CE6) | sysvinit-utils | 3.14-4 | not listed | LOW | affected |
| [TEMP-0628843-DBAD28](https://security-tracker.debian.org/tracker/TEMP-0628843-DBAD28) | login.defs | 1:4.17.4-2 | not listed | LOW | affected |
| [TEMP-0628843-DBAD28](https://security-tracker.debian.org/tracker/TEMP-0628843-DBAD28) | passwd | 1:4.17.4-2 | not listed | LOW | affected |
| [TEMP-0841856-B18BAF](https://security-tracker.debian.org/tracker/TEMP-0841856-B18BAF) | bash | 5.2.37-2+b10 | not listed | LOW | affected |
| [CVE-2026-82560](https://avd.aquasec.com/nvd/cve-2026-82560) | perl-base | 5.40.1-6+deb13u1 | not listed | UNKNOWN | affected |
| [DSA-6549-1](https://security-tracker.debian.org/tracker/DSA-6549-1) | liblzma5 | 5.8.1-1+deb13u1 | 5.8.1-1+deb13u2 | UNKNOWN | fixed |
| [TEMP-1147318-639065](https://security-tracker.debian.org/tracker/TEMP-1147318-639065) | liblzma5 | 5.8.1-1+deb13u1 | 5.8.1-1+deb13u2 | UNKNOWN | fixed |

