# HostsFileGet Roadmap

Living roadmap of features — what shipped, what's queued, and what's still being researched. Organized by theme, not by date.

Legend:
- ✅ Shipped
- 🚧 Implemented on `main` / pending release
- 📋 Backlog (researched, not yet built)
- 🔬 Research / speculative

---

## 1. Safety & Recovery

- ✅ **Timestamped rotating backups** — keep `N=5` snapshots `hosts.YYYYMMDD-HHMMSS.bak` alongside the rolling `hosts.bak`
- ✅ **Disable / Enable hosts** — replace hosts with minimal Microsoft template, stash original as `hosts.disabled`, swap back on re-enable
- ✅ **Hosts Health Scan** — flag non-loopback, non-LAN redirects as probable malware hijack indicators
- ✅ **Revert to Backup with preview** — diff current vs `.bak` before restore
- ✅ **Emergency DNS Recovery** — external `.bat` that force-kills Dnscache and installs a blank hosts file
- ✅ **Panic Restore** — one-click restore to stock Microsoft default (distinct from generic backup restore)
- ✅ **Backup diff viewer** — pick any two snapshots and compare side-by-side
- ✅ **Configurable retention** — let the user choose how many timestamped backups to keep
- 📋 **Hosts file ACL / read-only lock after save** — prevent malware tampering (HostsMan parity)
- ✅ **Integrity alarm** — detect external modifications since last save and prompt

## 2. Imports & Curated Sources

- ✅ **NRD feed** (xRuffKez Newly-Registered-Domains, 14/30 day) — high-value for phishing defense, low false-positive rate
- ✅ **CNAME-cloaking blocklist** — ship curated NextDNS CNAME-cloak list (Eulerian, Keyade, Criteo first-party trackers)
- 📋 **Category bundles** — one-click Adult / Gambling / Social / Dating / Piracy / Streaming presets sourced from OISD/StevenBlack categorized feeds
- 📋 **Vendor telemetry toggles** per OS/device (NextDNS-flagship style) — Apple/Samsung/Xiaomi/Windows/Roku/LG WebOS
- ✅ **Curated source catalog** — now 160+ sources across Major, Ads, Tracking, Telemetry, Malware, Phishing, Category Filters, Regional, Vendor/Platform groups (+56 added in v2.12)
- ✅ **Custom persistent user sources**
- ✅ **pfSense DNSBL log import**
- ✅ **NextDNS CSV import**
- ✅ **Manual paste import**
- ✅ **Batch Import dialog** with select-all / select-none
- ✅ **Import Mode** — Raw vs Normalized
- ✅ **50 MB download cap + gzip-bomb guard**
- ✅ **Source "Peek" preview** — fetch first ~80 lines before committing to import
- ✅ **Per-source last-fetched timestamp** — tooltip shows "3 days ago"
- ✅ **Scheduled auto-update** via Windows Task Scheduler integration
- ✅ **Update-on-launch** opt-in (admin-gated, stale sources only)
- 📋 **Silent background update mode** — headless exit-code-only, toast on completion
- ✅ **`--update` CLI flag** — re-fetch every previously-imported source
- ✅ **Per-source stale indicator**
- 📋 **Group/folder organization for custom sources** — drag-to-reorder, collapsible
- ✅ **Remove imported source section** without deleting it
- 📋 **Import from URL-based source list file** (`.dat`/`.txt`) for team sharing
- 📋 **Parse additional logs** — Pi-hole FTL, AdGuard Home, Technitium, OPNsense, Unbound blockfile, dnsmasq logs
- 🔬 **ETag / Last-Modified caching** — skip unchanged sources on re-fetch
- 🔬 **Mirror / fallback URL** per source — if primary 404s, try the jsDelivr / statically mirror
- 🔬 **Parallel source fetcher** — `asyncio`+`aiohttp` to refresh 56 sources at once; cuts minutes to seconds
- 🔬 **Gravity-style consolidated SQLite DB** (Pi-hole mental model) — domains + adlists tables, dedupe at import, 10× faster diff for 1M+ entries
- 🔬 **Cosmetic-rule quarantine** — on AdGuard-syntax import, split off `##` cosmetic rules to a separate file with export-as-uBO-user-filters option
- 🔬 **DGA heuristic scorer** — local n-gram Markov model flags unknown domains as DGA-likely without needing a feed
- 🔬 **Typosquat watchdog** — given a list of brands you own, generate Levenshtein-1 / homoglyph / bitsquat permutations and probe DNS for active squats
- 🔬 **LLM-endpoint opt-out pack** — curated OpenAI/Anthropic/Gemini/Perplexity endpoints with toggles for "block inference" / "block telemetry" / "block training crawlers" (GPTBot, ClaudeBot, Google-Extended)
- 🔬 **State-aligned media pack** — RT/Sputnik/CGTN/PressTV with citations to the enforcement source (EU sanctions, OFAC)
- 🔬 **Ad-verification bypass pack** — DoubleVerify, Moat, IAS bot-detection beacons
- 🔬 **Rugpull / crypto-scam adapter** — Chainabuse + CryptoScamDB + ScamSniffer JSON → hosts with 48h freshness gate

## 3. Editor & UX

- ✅ **Catppuccin Mocha dark theme**
- ✅ **Live stats panel** — total, final active, duplicates, whitelist-removed, normalized
- ✅ **Live badges** — Admin state, editor state, import mode, write mode
- ✅ **Debounced inline warnings** — red = discard, yellow = normalize
- ✅ **Search: Find / Prev / Next / Remove matching**
- ✅ **Sidebar source filter** (name/category/URL/tooltip)
- ✅ **Editor right-click context menu** — Whitelist domain, Copy domain, Toggle comment, Remove line, Check domain
- ✅ **Ctrl+/ toggle comment** on selection
- ✅ **Syntax highlighting** — IP / domain / comment coloring
- ✅ **Line numbers in editor gutter**
- 📋 **Drag-and-drop file import** (requires `tkinterdnd2`)
- ✅ **Portable mode** — detect sibling `settings.json` and use it instead of `%APPDATA%`
- 📋 **Adblock-syntax linter** inline in editor
- 📋 **Regex-based whitelist/blacklist patterns** with live match preview
- 📋 **Redirection rules** — `(hostname → custom IP)` tracked separately from blocks
- 📋 **Regex + exact + wildcard tiers** — expose the distinction (AGH-style) instead of conflating all three
- 📋 **IDN / punycode toggle** — render `xn--` as Unicode with Cyrillic/Latin homoglyph spoof warning
- 🔬 **Collapsible import sections** — fold everything between `# --- Import Start/End ---` markers
- 🔬 **Multi-cursor edits** — Ctrl+click multiple lines and edit simultaneously (VSCode-style)
- 🔬 **Bookmarks / pinned lines** — mark a line, jump back with Ctrl+1..9
- 🔬 **Clipboard history ring** — last 20 copied hosts entries, quick re-paste
- 🔬 **sed-style command bar** — `Ctrl+R` opens `s/0.0.0.0/127.0.0.1/g`, `d/^#.*ads/`, `g/doubleclick/p`
- 🔬 **Query language** — `SELECT domain WHERE source='OISD' AND added_after='2026-01-01'` → CSV
- 🔬 **Diff-against-pasted-text** — paste a snippet; highlight which lines are new vs already-present
- 🔬 **Gas Mask `@group` syntax** import — support Mac editor dialect for migrations

### 3a. Navigation & Discovery (inspired by VSCode / Sublime / JetBrains)

- 📋 **Sticky source header** — pin current source block header ("# StevenBlack unified") at top of viewport as you scroll — orientation in 100k-line files
- 📋 **Breadcrumb trail** — clickable `Profile > Source > Category > Domain` above editor
- 📋 **Minimap with heatmap overlay** — standard minimap colored by recency of DNS hits (from imported log parsers)
- 📋 **Peek source** — hover a domain + hotkey → inline popup of every source that lists it, no navigation
- ✅ **Goto-anything fuzzy** — one dialog ranks domains / comments / source names / profiles / bookmarks
- 📋 **Structural search/replace** — "all `*.cdn.*` under source X with comment containing 'tracker'"
- 📋 **Refactor preview pane** — diff before committing a bulk rename/merge

### 3b. History, Provenance & Versioning (Git clients / Lightroom)

- 📋 **Blame gutter** — left margin shows which source/import/edit introduced each line, timestamp on hover
- 📋 **History brush / timeline scrubber** — slider reveals the file state at any past point, entries color-coded by age
- 📋 **Before/after toggle** — hotkey flips between current state and last-imported state
- 📋 **Non-destructive edits stack** — each change a reversible layer, toggle on/off independently (Lightroom-style)
- 📋 **Provenance trail panel** — for any entry, full lineage: first imported from X on date, modified by Y, commented by Z

### 3c. Safety, Secrets & Trust (Password managers)

- 🔬 **Vault-protected entries** — sensitive whitelist rules (banking) require master-password unlock to view/edit
- 🔬 **Reveal-on-hover comments** — notes masked as dots until hovered (screen-share safety)
- 📋 **Trust badges per source** — signed / verified / unknown based on hash-pinning + HTTPS provenance

### 3d. Organization & Curation (Email / RSS / Notion)

- 📋 **Focused vs Other split** — auto-partition imports into "curated official" and "user ad-hoc" tabs
- ✅ **Star/pin entries** — flag high-value rules, survive wipes, appear in "Starred" smart view
- 📋 **Unreviewed badge** — new imports carry unread dot until viewed in diff
- 📋 **Tag sidebar** — multi-tag entries with free-form labels (`tracker`, `ads`, `work-only`)
- 📋 **Backlinks panel** — show every source/note/profile that references a given domain
- 🔬 **Graph view** — domain clusters by shared subdomain / source overlap / tag co-occurrence (Obsidian-style)
- 🔬 **Inline Markdown notes** — rich notes with fenced code/links/images attached to entries

### 3e. Querying & Data Work (Database GUIs)

- 📋 **Query history panel** — every regex/filter logged, re-runnable, pinnable
- 📋 **Filter builder GUI** — `source = X AND tag = Y AND last_hit > 30d` without typing
- 📋 **CSV/JSON round-trip** — export rows, edit in Excel, re-import with conflict resolution

### 3f. Power-User & Keyboard-First (Alfred/Raycast/vim)

- 📋 **Global hotkey quick-add overlay** — system-wide hotkey → tiny popup; type domain, enter, added, main app never opens
- 📋 **Slash commands in entry field** — `/import`, `/diff`, `/backup` trigger actions without menus
- 📋 **Command history scrollback** — Up-arrow walks prior commands, fzf-filterable
- 🔬 **Which-key popup** — after leader key, popup reveals available chords *(opt-in; conflicts with "no keyboard shortcuts" default — gate behind a pref)*

### 3g. Intelligence & Assistance

- 📋 **Typo suggestions** — "did you mean `doubleclick.net`?" on misspelled whitelist additions
- 📋 **Inline ghost-text completion** — subdomain completions from known tracker databases as you type
- 📋 **Confidence badges** — "99% of users block this" / "uncommon block" per entry
- 📋 **Source library icons** — fetched favicon per source in the catalog (Playnite-style visual recognition)
- 🔬 **Achievement milestones** — toasts at "100k blocked" / "1 year clean" / "first custom rule"
- 🔬 **Recently imported shelf** — dashboard card with last 5 source updates + counts + dates

### 3h. Review, Spaced Repetition & Monitoring

- 📋 **Stale entry review queue** — entries not seen in DNS logs for N days surface in a "maybe remove?" queue (Anki-style)
- 📋 **Watch expressions** — persistent "notify me when `*.x.com` appears in any imported source"
- 📋 **Conditional rules** — activate only when VPN on / work network / date range (IDE-debugger conditional breakpoints)

### 3i. Polish, Output & Workflow

- 📋 **Post-action hooks** — after save/apply/import, run user-defined scripts (flush DNS, webhook, git commit) — ShareX post-capture pattern
- 📋 **Copy-as-screenshot** — right-click selection → styled PNG of entries on clipboard (bug-report / Discord share)
- ✅ **First-run wizard** — "Block ads? Trackers? Adult? Social? Gambling?" → preselect curated sources (Linear/Figma-style onboarding)
- ✅ **Sources Report (Top-N)** — rank by total / duplicate / unique contribution (Process Explorer top-N)
- ✅ **Kill-all-from-source** — right-click source header → "remove all 47,213 entries from this source" (Task Manager kill-tree)
- 📋 **Zen mode** — fullscreen, hide chrome, single column, generous whitespace for curation sessions (iA Writer / VSCode Zen)
- 📋 **Stat HUD** — corner overlay: entries count / duplicates / avg age / profile size delta — always-on situational awareness

## 4. Cleanup & Transformations

- ✅ **Auto-Clean + Preview** — dedupe, normalize, whitelist-filter, produce canonical sorted output
- ✅ **Normalize & Deduplicate**
- ✅ **pfSense / NextDNS log → hosts** conversion
- ✅ **Convert Block IPs** — rewrite all loopback-style sinks to `0.0.0.0`, `127.0.0.1`, or `::`
- ✅ **Granular cleanup commands** — "Delete comments only", "Delete empty lines only", "Delete invalid lines only"
- 📋 **Batch operations** — sed/awk-style find-and-replace with preview
- 🔬 **Streaming parser for 1M+ entry files** — mmap-backed editor pane for huge lists

## 5. Diagnostics & Insight

- ✅ **Flush DNS** — `ipconfig /flushdns` from inside the app
- ✅ **Check Domain tool** — is it blocked? whitelisted? which previously-fetched sources contain it?
- ✅ **Hosts Health Scan** — flag suspicious non-loopback redirects
- ✅ **Built-in DNS resolver** — resolve a domain bypassing hosts, report its real IP
- ✅ **Ping / connectivity test** from the editor context menu
- 📋 **"Which source blocked this?"** inverse lookup — show every curated list that contains a given domain
- 📋 **Per-category stats breakdown** — "40k ads, 15k telemetry, 8k malware"
- ✅ **Top-contributing sources report** — which list added the most unique domains this session
- 📋 **Source overlap matrix** — redundant-source pruning insight
- 📋 **Historical growth chart** — sparkline from saved backup snapshots
- 📋 **Allowlist audit log / provenance sidecar** — who-added-what-when tracked in `hosts.provenance.json` (AGH 0.107+ parity)
- 📋 **Tray badge counter** — uBO-style numeric badge showing blocks-since-midnight from DNS Client log (see §12)
- 📋 **"Logger" live tail view** — mini window tails the nearest available DNS query log and highlights hits against current hosts
- 🔬 **Blocked-query trend** — parse imported logs and render a 30-day histogram
- 🔬 **Registrar sankey** — Domain → Registrar → Registrant-Country flow view reveals when 40% of blocks trace to one bulletproof registrar
- 🔬 **Category treemap explorer** — leaf size = domain count, color = last-seen freshness; drill into source
- 🔬 **Per-source sparklines** — inline entry-count-over-30-days spark on source panel; spot collapsed feeds instantly
- 🔬 **Redirect-chain force graph** — render observed HTTP redirect chain for a blocked domain before apply
- 🔬 **ECH/ESNI awareness** — flag entries where hostname blocking is futile (Cloudflare ECH-enabled list); recommend IP-range alternative
- 🔬 **DoH canary toggle** — one-click block for `use-application-dns.net` + Chrome's `dns.google` probe
- 🔬 **Encrypted-DNS client handoff** — detect YogaDNS/DNSCrypt/Simple-DNSCrypt and warn "your resolver is overriding hosts for these 12 domains"
- 🔬 **DoH/DoT bootstrap pairing** — when blocking a domain that would otherwise break the user's DoH resolver discovery, auto-suggest adding the resolver's IP as a bootstrap hosts entry

## 6. Profiles & Environments

- 📋 **Multiple named hosts profiles** — Work / Gaming / Full Block / Minimal — swap active with one click
- 📋 **Client-group emulation (Pi-hole v6 style)** — per-device profiles (Kids-PC / Work-Laptop) that generate different hosts outputs per target
- 📋 **Layered/merge profiles** — a profile that references other local + remote files and merges on activation
- 📋 **System tray icon with quick-switch** — right-click tray to swap profile without opening main window
- 📋 **Profile export/import** — portable file for team distribution
- 📋 **Game-profile presets** — "Riot Vanguard" / "Easy Anti-Cheat" / "BattlEye" / "Denuvo" / "Roblox Hyperion" that *unblock* telemetry each anti-cheat requires
- 📋 **Steam/Epic/Battle.net CDN allowlist** — pre-built safe-list so downloads aren't throttled
- 📋 **Console telemetry sheets** — PS5 / Xbox / Switch per-platform block sets (built here, deployed via router)
- 📋 **Roblox safe-chat mode** — block social+chat endpoints, preserve gameplay (kid-safety)
- 📋 **Twitch rotating ad-CDN toggle** — auto-refresh from community feed
- 🔬 **Conditional profiles** — auto-switch based on Wi-Fi SSID or VPN status

## 7. Scripting & Automation

- ✅ **CLI args**: `--version`, `--disable`, `--enable`, `--backup`, `--apply PATH`
- 📋 **`--update`** — re-fetch previously imported curated sources headlessly
- 📋 **`--profile NAME`** — apply a named profile
- 📋 **Windows Task Scheduler wizard** — one-click create scheduled task for `--update` or `--apply`
- 📋 **PowerShell module wrapper** — `Import-HostsFileGet`, `Enable-Hosts`, etc.
- 🔬 **Webhook / notification hooks** — POST to a URL on save / update success

## 7b. Windows Deep Integration

- 🔬 **WFP ALE Layer IP Blocker** — Windows Filtering Platform driver hook (`FwpmEngineOpen0`) closes the gap where a blocked domain resolves via DoH bypass; blocks at IP/CIDR level
- 🔬 **NRPT Policy Surgeon** — GUI for `Add-DnsClientNrptRule`; pin `.corp.local` to internal DNS while global hosts stays ad-focused; export as `.pol` for GPO
- 🔬 **Surgical DNS cache flush** — per-entry eviction via `DnsFlushResolverCacheEntry_W` with pre-flush hit-count from `Get-DnsClientCache`
- 🔬 **Windows Sandbox `.wsb` generator** — emits mapped-folder config with a logon command that copies hosts, for sandboxed browsing against the live blocklist
- 🔬 **Hyper-V Gen2 injector** — pushes hosts into running VMs via `hvsocket`, no VM networking round-trip
- 🔬 **Credential Guard-aware signing** — signs hosts with a cert stored in the VBS-isolated key store so VTL0 malware can't forge
- 🔬 **Reliability Monitor provider** — register as `System.Reliability` source so hosts edits show up next to driver installs in the reliability timeline
- 🔬 **Storage Sense exclusion registrar** — auto-register the backup vault so aggressive cleanup doesn't wipe rollback history

## 1b. Extended Recovery Paths

- 🔬 **WinRE ReAgent hook** — registers `ReAgentc /setosimage` custom tool; Shift+Restart → Advanced Options → "Repair Hosts File"
- 🔬 **BitLocker-aware recovery partition** — writes signed recovery hosts to unencrypted WinRE partition so recovery works pre-unlock
- 🔬 **VSS writer** — real `IVssWriter` implementation so Veeam / Macrium / Windows Backup capture hosts transactionally
- 🔬 **System Restore integration** — call `SRSetRestorePoint` before batch apply; rollback = one-click System Restore
- 🔬 **Safe Mode escape hatch** — `SafeBoot\Minimal\HostsFileGetSafe` service strips hosts to known-good minimal on Safe Mode boot

## 7c. Router & Gateway Ecosystem

- 📋 **pfBlockerNG DNSBL bidirectional sync** — keep pfSense DNSBL and Windows hosts consistent
- 📋 **OPNsense Unbound override pusher** — SSH+API push as `local-data:` overrides with diff preview
- 📋 **OpenWrt uci bridge** — emit `/etc/config/dhcp` dnsmasq blocks, push via `uci import` over SSH
- 📋 **MikroTik RouterOS script generator** — `/ip dns static add` scripts for CHR and hardware devices, TTL + regex-match aware
- 📋 **Squid `domain_acl` mirror** — generate `acl blocklist dstdomain "/etc/squid/hostsfile.acl"` fragments for transparent proxy reuse

## 7d. Parental Controls & Family Safety

- 📋 **Windows Family Safety bridge** — read Microsoft Family Safety web-filter list via Graph API, reconcile with local hosts
- 📋 **Per-SID scheduled profiles** — Task Scheduler jobs keyed on user SID swap profiles when a specific account logs in (kid = strict, admin = permissive)
- 📋 **Homework Mode countdown tray** — countdown with auto-restore on expiry, overrides logged to Event Log for parent review
- 📋 **Chore Reward whitelist token** — HMAC-signed one-shot token (QR/NFC) that temporarily unblocks for N minutes, non-replayable
- 📋 **SafeSearch lock via CNAME pinning** — map google/bing/ddg to forcesafesearch A records, alarm on override

## 7e. Browser-Specific Integration

- 📋 **Enterprise ADMX companion** — Chrome/Edge managed policy `HostsFileGetBypass` so SSO/ADFS domains are exempt from hosts redirection at the browser layer
- 📋 **`proxy.pac` emitter** — convert blocklist to Firefox/Chromium proxy.pac (`return "PROXY 0.0.0.0:1";` for blocked domains); survives DoH since browser picks proxy pre-resolution
- 📋 **WebRTC leak domains bundle** — curated STUN/TURN endpoint blocklist, toggleable per profile

- ✅ **Export hosts format** (original behaviour of `Save Raw`)
- ✅ **Export Cleaned As…** — hosts / domains-only / adblock / dnsmasq / pi-hole
- ✅ **Import from Pi-hole FTL database** (`pihole-FTL.db`) — blocked queries → hosts (direct SQLite, SMB/SSH-friendly)
- ✅ **Import from AdGuard Home querylog.json** — streaming JSONL + live-tail mode
- 📋 **Technitium REST API client** — query blocked-queries endpoint
- 📋 **Unbound / dnsmasq log tailers** — regex-based, format auto-detection
- 📋 **OPNsense/pfSense Unbound syslog listener** — listen UDP/514 locally, ingest blocked-query events
- 📋 **BIND RPZ log ingest** — parse `rpz-nsdname`/`rpz-ip` hits from `named.log`
- 📋 **Windows DNS Client ETW tap** — subscribe to `Microsoft-Windows-DNS-Client` provider for real-time local-query stream, no log file needed
- 📋 **Git-versioned hosts files** — detect `.git` in config dir, stage+commit on save
- 📋 **SSH push to remote `/etc/hosts`** — one-click deploy to pfSense jail / Raspberry Pi / homelab Linux box (paramiko)
- 📋 **WSL2 resolv.conf warning** — detect and alert when users expect WSL to inherit Windows hosts (it often doesn't)
- 🔬 **MDM / Intune `.intunewin` export** — wrap hosts + install script as Intune Win32 app for org-wide push
- 🔬 **GPO / ADMX snippet generator** — emit GPP File-copy XML, drop into SYSVOL, done
- 🔬 **SCCM / PDQ Deploy package export** — `.ps1` wrapper + hosts payload zipped
- 🔬 **Ansible playbook / Terraform `local_file` export** — hosts rendered as declarative IaC artifact
- 🔬 **Community allowlist repo** — curated whitelists for Zoom/Teams/banking pulled from a vetted GitHub org

## 9. Security / Forensics / OSINT

- ✅ **Source-name injection hardening** — strip CRLF/tabs from import markers
- ✅ **HTML-response guard** — reject `<html>…</html>` payloads masquerading as hosts
- 📋 **VirusTotal lookup** for domains flagged by Health Scan (4 req/min free tier, cache aggressively)
- 📋 **MalwareBazaar integration** — cross-check suspicious redirects
- 📋 **URLhaus (abuse.ch) live feed** — built-in malware blocklist source with live threat counts
- 📋 **Export hosts as YARA rule** — generate a YARA sig for the full blocklist for IR teams running YARA on proxy logs
- 📋 **IOC import (STIX 2.1 / MISP)** — pull domain indicators from a MISP instance, auto-rotate on IOC expiry
- 📋 **Phishing-kit feed integration** — PhishTank + OpenPhish with 48h auto-expire (phishing has short lifespan)
- 📋 **Certificate Transparency watchlist** — monitor crt.sh for newly-issued certs matching user brand patterns (e.g. `paypal*`); auto-block typosquats as they appear
- 📋 **Signed-manifest mode** — sign hosts with an Ed25519 keypair, embed signature as a comment; on-launch verify and alert on tamper
- 📋 **Read-only "approved-entries" mode** — lock corporate-managed lines (greyed + unremovable) while allowing user additions below (Chrome managed-policy mental model)
- 🔬 **LLM-assisted "why is this blocked?"** — pull filter-list metadata and summarize the reason a domain is on the list (offline pre-built domain→reason DB)
- 🔬 **Smart whitelist suggestions** — broken-site reports scan recent hits for that TLD, small bundled classifier ranks likely offender
- 🔬 **Natural-language rule entry** — "Block all TikTok telemetry" → LLM + curated map expands to correct domain set (opt-in, local Ollama or API key)
- 🔬 **Auto-categorize custom entries** — paste 200 domains, LLM sorts into ads/tracking/malware/social
- 🔬 **TLS certificate preview** — show cert chain for a highlighted domain (helps decide "real or phishing")

## 10. Platform & Packaging

- ✅ **Windows admin auto-elevation** (UAC prompt) with elevation-loop guard
- ✅ **High-DPI awareness**
- ✅ **PyInstaller bundle (`HostsFileGet.spec`)**
- ✅ **PowerShell WPF splash launcher** (`PythonLauncher.ps1`)
- ✅ **`%LOCALAPPDATA%` config with atomic writes**
- 📋 **PyInstaller CI workflow** — Windows build on push/tag
- 📋 **Code-signed release artifacts**
- 📋 **Winget manifest** for `SysAdminDoc.HostsFileGet`
- 🔬 **macOS `/etc/hosts` port** — Catppuccin-themed SwiftUI or Qt wrapper reusing the Python core
- 🔬 **Linux AppImage** with polkit elevation

## 10a. Developer Workflow

- 📋 **VS Code companion extension** — syntax highlighting, hover-preview source attribution, "Test this rule" codelens that pings the resolver, live-diff sidebar against remote sources
- 📋 **prompt_toolkit TUI** — full-screen terminal mode for SSH/serial-console admins, fuzzy search, live DNS event tail
- 📋 **REPL rule tester** — `hostsfileget repl` drops into interactive shell; type a domain, see matching source(s) + override chain resolution
- 📋 **Local REST facade** — `127.0.0.1:47823` GET/POST/DELETE for entries with bearer-token auth; enables Ansible/Chef/PowerShell DSC modules to manage hosts declaratively

## 10b. Declarative / DevOps

- 📋 **YAML/TOML declarative source-of-truth** (`hosts.yaml`) — sources/allowlist/profiles described, hosts file becomes a generated artifact; `hostsfileget build` deterministic
- 📋 **Git-backed hosts repo mode** — every apply is a commit ("Added 412 domains from OISD"); rollback = `git revert`
- 📋 **GitHub Actions template** — nightly rebuild from declarative config, opens PR if diff > threshold
- 📋 **`pre-commit` lint hook** — standalone lint binary for CI flags invalid IPs, duplicate domains, punycode mismatches, TLD typos
- 🔬 **Webhook / notification hooks** — POST to a URL on save / update success
- 🔬 **Hot-reload daemon** — background service watches declarative YAML, regenerates on save

## 10c. Collaboration

- 📋 **Shareable whitelist patches (`.hfgpatch`)** — signed allowlist additions + reason; team members apply with one click + diff
- 📋 **GitHub Gist sync** — settings + custom entries sync to a secret Gist for multi-machine roaming
- 📋 **Merge-request review mode** — side-by-side diff of a proposed hosts change with approve/reject/comment

## 10d. Accessibility & i18n

- 📋 **High-contrast + dyslexia-friendly font toggle** — OpenDyslexic / Atkinson Hyperlegible bundled, per-user remembered
- 📋 **IDN / punycode toggle with homoglyph warning** — render `xn--` as Unicode, flag Cyrillic-Latin spoofs
- 🔬 **Screen-reader-friendly tree mode** — alternative nav: source → category → domain with accessibility labels
- 🔬 **RTL-aware editor** — Arabic/Hebrew comments render correctly

## 10e. SSL / Zero Trust

- 🔬 **Cloudflare Access policy sync** — import Cloudflare Zero Trust Gateway block categories via API, merge with hosts so off-WARP endpoints keep parity
- 🔬 **HTTPS downgrade guardrail** — refuse to load any source rule mapping a domain to a non-loopback IP unless user confirms; prevents malicious feeds from silent SSL-strip via hosts

## 11. Tests & Quality

- ✅ **42 pure-function unit tests** — parsing, normalization, cleanup stats, sanitization, HTTP limits
- 📋 **Property-based tests** for `normalize_line_to_hosts_entries` (Hypothesis)
- 📋 **Tk widget smoke tests** via `pytest-tk` or `pyvirtualdisplay`
- 📋 **Golden-file diff tests** for the Cleaned Save output
- 📋 **Source-schema fuzzer** — Hypothesis-driven BOM/CRLF/UTF-16/comment-style mutations per source; prove parser survives adversarial feeds
- 📋 **Chaos dependence detector** — nightly randomize-disable one source, diff resulting blocklist; alert if any single source provides >25% of unique entries
- 📋 **Canary domain heartbeat** — maintain 3 owned canary domains in blocklist; watchdog confirms they fail to resolve post-apply, catches silent corruption
- 🔬 **Benchmark regression suite** — ensure 50K-line files stay under a defined rebuild ms budget

## 12. Performance & Scale

- 📋 **Virtual-scroll / mmap-backed editor** for 500k+ line files — render visible window only (Tk Text can't natively)
- 📋 **Streaming chunked parser** — process 2M-line lists in 10k chunks, never freeze UI
- 📋 **Differential updates** — per-source ETag/Last-Modified cache; skip unchanged
- 🔬 **Bloom-filter dedupe during import** — 10× memory reduction vs `set()` for massive lists
- 🔬 **Compiled blocklist cache** — post-dedupe sorted+zstd cache; re-apply is a copy, not a rebuild

---

*This roadmap is appended to as new research lands. See `CHANGELOG.md` for shipped history.*
