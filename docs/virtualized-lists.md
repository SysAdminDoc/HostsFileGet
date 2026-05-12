# Virtualized Large Lists

HostsFileGet keeps the main editor as a Tk `Text` widget, but large review dialogs must avoid creating thousands of child widgets at once.

## Match Removal

The **Remove Matches** flow now uses a paged checkbox view:

- only 200 matching rows are rendered at once
- page size is capped to 500 rows internally
- selection state is global across all pages
- **Select All** and **Select None** apply to the full match set, not just the visible page
- the final preview still shows the exact lines that will be removed

This replaces the previous fallback that forced very large match sets into an all-or-nothing preview.

## Boundaries

- The main editor is not replaced in this step.
- The helper is intentionally generic (`build_virtual_list_page`) so other large dialogs can adopt it without a widget rewrite.
- Search highlighting still has a hard cap to protect Tk tag performance.
- Performance-sensitive UI changes should continue to use the large-file benchmark and GUI smoke tests.
