# Licence review of bundled and called tools

Attestra itself is the project's own code. External scanners are never linked
into Attestra: they run as separate processes (the runner builds an argv and
executes it without a shell) or, for copyleft network services, as separate
services reached over HTTP. Importers only parse the tools' output files.

Reviewed 2026-10-14. Re-check on each tool upgrade; licences can change between
releases.

| Tool | Licence | How Attestra uses it | Notes |
| --- | --- | --- | --- |
| OWASP ZAP | Apache-2.0 | Separate process / container (`runner/scanners/zap.py`) | Permissive. |
| Nuclei | MIT | Separate process (`nuclei.py`) | Templates (nuclei-templates) are MIT. |
| Trivy | Apache-2.0 | Separate process (`trivy.py`) | Vulnerability DB has its own terms; downloaded by the operator. |
| Semgrep CE | LGPL-2.1 (engine) | Separate process (`semgrep.py`) | Registry rules ("--config auto") are under the Semgrep Rules License, which restricts use in competing SaaS products; review before offering scans as a hosted service. |
| Prowler | Apache-2.0 | Separate process (`prowler.py`) | Permissive. |
| kube-bench | Apache-2.0 | Separate process on the cluster node (`kube_bench.py`) | CIS benchmark text is CIS copyright; reports cite check ids only. |
| testssl.sh | GPL-2.0 | Separate process (`testssl.py`), not bundled | Calling it as a program does not make Attestra a derivative work. If a container image that includes testssl.sh is distributed, GPL source-offer obligations apply to that image. |
| Gitleaks | MIT | Separate process (`gitleaks.py`), always with `--redact` | Permissive. |
| Checkov | Apache-2.0 | Separate process (`checkov.py`) | Permissive. |
| naabu | MIT | Separate process (`naabu.py`), pinned IP only | Uses libpcap (BSD) for SYN scans when run privileged. |
| OpenVAS / Greenbone (gvmd, ospd-openvas) | AGPL-3.0 / GPL-2.0+ | Separate HTTP service only, off by default (`http_service.py`, `ATTESTRA_OPENVAS_ENABLED`) | Never bundled or linked. AGPL obligations apply to whoever operates a modified service. Greenbone Community Feed has its own licence terms. |
| MobSF | GPL-3.0 | Separate HTTP service only, off by default (`ATTESTRA_MOBSF_ENABLED`) | Never bundled or linked. |
| Nmap | Nmap Public Source License (NPSL) | Not used | NPSL restricts redistribution in commercial products; naabu is used for port discovery instead. Do not bundle Nmap without an OEM licence. |

## Python dependencies

Python dependencies are listed in `pyproject.toml`. Run a licence report
(for example `pip-licenses --from=mixed`) before each release and record any
copyleft dependency here.

## Rules

1. A GPL/AGPL/NPSL tool is never imported as a library, vendored, or copied into Attestra's images.
2. Copyleft network services are optional, off by default, and configured by URL.
3. Every new tool gets a row in this table before its adapter is merged.
