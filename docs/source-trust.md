# Source Trust Badges

HostsFileGet shows source trust badges beside curated and saved feeds. The badges are transparent signals, not endorsements.

## Criteria

| Badge | Meaning | Action |
| --- | --- | --- |
| `Curated` | The feed is listed in the bundled catalog. | Treat as reviewed metadata, not guaranteed-safe content. |
| `Saved` | The feed was added by the local user. | Review the upstream project before reuse. |
| `HTTPS` | The feed URL uses encrypted transport. | Still inspect content because upstream can change. |
| `HTTP` | The feed URL is not encrypted. | Prefer HTTPS or manually verify before import. |
| `GitHub-backed` / `GitLab-backed` | The URL maps to a repository path. | Use the derived issue path for false-positive or broken-feed reports. |
| `CDN mirror` | The URL is served through jsDelivr and maps back to a GitHub repository path. | Report source problems to the backing repository, not the CDN. |
| `Direct host` | No repository path could be derived. | Use the feed owner's published support channel. |
| `License untracked` | The catalog does not yet record upstream license metadata. | Do not assume redistribution rights from the badge. |
| `Issue path` | HostsFileGet derived a GitHub/GitLab issue URL. | Prefer upstream reports for source-specific false positives. |
| `Report manually` | No issue URL could be derived. | Find the source owner's support route manually. |
| `Review scope` | The source name, category, or description suggests broad, aggressive, adult-content, or special-format coverage. | Preview before importing and expect more false-positive risk. |
| `Fetched` / `Not fetched` | Local install freshness only. | This says nothing about upstream maintainer activity. |
| `Cache verified` | A cached body exists with matching SHA-256 metadata. | This only verifies local cache integrity. |

## Non-Claims

- Badges do not certify that a feed is safe.
- Badges do not check live maintainer activity.
- Badges do not verify upstream licenses yet unless future catalog metadata records one.
- Badges do not prove that a feed has low false positives.

The source health checker and preview dialog should be used with these badges before importing unfamiliar or aggressive feeds.
