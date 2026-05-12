# SafeSearch And Restricted-Mode Templates

HostsFileGet includes plan-only SafeSearch and restricted-mode templates for environments that want reviewable search/video safety mappings next to their hosts-file workflow.

## Why This Is Plan-Only

Provider enforcement differs by service:

- Google documents SafeSearch VIP enforcement through `forcesafesearch.google.com` and notes DNS CNAME or VIP-style mapping patterns: <https://support.google.com/websearch/answer/186669?hl=en>
- Google Workspace/YouTube documents restricted and moderate restricted DNS targets for selected YouTube hostnames: <https://support.google.com/a/answer/6212415?hl=en>
- Microsoft documents strict Bing SafeSearch through `strict.bing.com` mappings: <https://support.microsoft.com/topic/block-adult-content-with-safesearch-or-block-chat-11546adf-1bbc-4c2e-9ef9-fbd6799bc79d>
- DuckDuckGo documents network-level Safe Search with a DNS CNAME to `safe.duckduckgo.com`: <https://duckduckgo.com/duckduckgo-help-pages/features/safe-search/>
- Managed DNS products such as NextDNS and AdGuard DNS expose broader parental-control workflows beyond local hosts-file edits: <https://nextdns.io/> and <https://adguard-dns.io/en/welcome.html>

The Windows hosts file can map hostnames to IP addresses. It cannot create CNAME records, wildcard all Google country domains, set browser policy, override hardcoded app behavior, or prevent encrypted-DNS/VPN bypasses.

## GUI

Open **Tools > SafeSearch / Restricted Mode Templates...**.

The dialog lists:

- hosts-reviewable templates for Google and Bing where a provider target can be resolved and converted into hosts lines;
- DNS handoff templates for DuckDuckGo and YouTube where CNAME records are the documented control;
- warnings about placeholders, provider IP drift, browser policy, and DNS-provider boundaries.

## CLI

```powershell
python hosts_editor.py --safesearch-template-list
python hosts_editor.py --safesearch-template-plan google .\google-safesearch-plan.json
python hosts_editor.py --safesearch-template-plan youtube .\youtube-restricted-plan.json
python hosts_editor.py --safesearch-template-plan yt-moderate .\youtube-moderate-plan.json
python hosts_editor.py --safesearch-template-plan duckduckgo .\duckduckgo-safe-plan.json
python hosts_editor.py --safesearch-template-plan bing .\bing-strict-plan.json
```

The JSON plan separates `hosts_line_templates` from `dns_cname_records`. Placeholder hosts lines such as `<resolved strict.bing.com IP>` must be resolved and replaced before use.

## Limits

- The CLI and GUI never apply these templates to the live hosts file.
- Provider IPs can change. Re-resolve provider targets immediately before turning a plan into hosts entries.
- YouTube and DuckDuckGo templates are DNS CNAME handoffs, not native hosts-file mappings.
- SafeSearch and restricted mode are not full parental controls. Pair them with browser/account policy, managed DNS, router/firewall controls, and encrypted-DNS bypass diagnostics where enforcement matters.
