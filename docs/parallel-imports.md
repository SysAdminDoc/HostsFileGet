# Parallel Source Imports

HostsFileGet batch imports now fetch multiple selected sources concurrently while preserving the selected source order in the final editor output.

## Behavior

- imports use up to 4 worker threads
- each source fetch can make up to 3 attempts before reporting failure
- successful imports are inserted in the same order the user selected them
- failures are logged per source and do not stop the rest of the batch
- conditional ETag/Last-Modified cache reuse still applies
- cached fallback bodies are still accepted when a source is temporarily unreachable

## Cancellation

The **Stop Import** button sets the same cancellation flag as before. In a parallel batch, pending futures are cancelled and the worker waits for already-running downloads to return before the UI finishes the cancellation.

## Implementation Notes

- `resolve_import_fetch_worker_count(...)` clamps concurrency to the selected source count and `IMPORT_FETCH_MAX_WORKERS`.
- `fetch_source_with_retries(...)` wraps `fetch_source_with_cache(...)` and reports the attempt count for status logging.
- `_import_worker_thread(...)` stores processed output by source index, then flattens the successful results in source order when the batch completes.

## Boundaries

- Source transformation still runs through the existing Raw/Normalized import mode.
- The retry helper retries raised fetch failures; cache fallback from `fetch_source_with_cache(...)` is treated as a successful fallback.
- The GUI thread still receives all state changes through `import_queue`.
