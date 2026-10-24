# Netlens interface rules

The rules every page follows, so a new page does not need a review round. Most are enforced by CSS or `app/static/js/actions.js`; the rest by habit and by the checklist at the end.

## Look
- **Corners:** containers (cards, tiles, dialogs, table frames, fieldsets) use `var(--radius)` (8 px); controls and chips use `var(--radius-sm)` (6 px); pills use 999 px. Never write a pixel value for a radius.
- **Space:** page padding 12 px, card padding 12 x 14 px, gaps 12 px. Do not add outer margins to cards to "breathe".
- **Frames:** a table has the soft frame (`.table-wrap`) unless it is inside a card.
- **No box around the main list of a page** (Storage, Backups): the list is the page.

## Buttons (`actions.js` enforces the colours)
- **Save / Apply / Create / Add (submit):** `btn primary`, blue and filled. It is the first button in its row (`order: -1` in `.form-actions` and `.btn-row`).
- **Cancel / Reset / Close / Back:** plain `btn`, after the save button.
- **Delete / Remove:** `btn danger`, red, last in the row. Inside a table row or list it is drawn as an outline.
- **One Save per page.** If a page has two independent parts, make two pages (see Settings -> AI language model and AI agents). Actions that are not saves (Test, Sync now, Run diagnostic) are plain buttons.
- Buttons never stretch across a wide card (`.field > button { justify-self: start }`).

## Forms
- Fields that follow each other sit side by side (auto-fill columns of at least 280 px) inside Settings; text areas and multi-selects take the whole row; fieldsets sit side by side too. Do not build a column of full-width fields.
- Single-line inputs and selects are at most 36rem wide.
- Settings live under Settings. A feature page (DNS, Vulnerabilities, Backups) holds results and actions and links to its settings ("Settings -> DNS registration"); it does not embed a settings form. Exception: a one-line schedule that belongs to the page (Speed tests).

## Lists and pages
- A list that can grow shows the newest few (6-10) with a "show all" button; logs page by 50.
- Several summary tiles use `.up-tiles` (auto-fit, 190 px minimum). A tile that signals a problem is clickable and leads to the page or row that explains it (`tile(..., target)`).
- Every problem shown anywhere links to the page that explains it, and the target opens the affected row (`?focus=problems` on Storage and Backups).
- Optional pages (Backups, Storage, Smart home, Vulnerabilities, DNS, Remote sites) are in the menu only when a plugin of that kind is on or data exists (`/api/features`, `data-feature` in `index.html`). Add a new optional page there.
- Long host names: show `shortName()` where space is tight; tables wrap, they never push the page sideways (no horizontal scroll on the page at 820 or 1400 px).

## Wide screens
- The dashboard grid is auto-fill with at most six columns; the device page flows in 2, 3 (>= 1900 px) or 4 (>= 2800 px) columns; long row lists (Uptime) use 2 or 3 columns.
- Settings cards are at most 1500 px wide.

## Layouts (cards the user can arrange)
- Every page of cards uses the editing kit of the Overview beta page: a Customize button, a grip to drag (touch too), a width button (narrow, wide, full) and a remove button on each card, and a drawer on the right with a tick box and a small picture per card (`js/board.js`).
- A new card page: put its cards in a `.dev-flow` grid (or call `gatherCards(root)`), tag each card (`data-card`, `data-title`, `data-kind`, `data-size`), create `boardPage("<page>", "<label>")` (add the page to `PAGES` in `app/layouts.py`), call `board.apply({tab: flow})` after every draw, put `board.button()` in the page head, do not redraw while `board.editing`, and call `board.close()` when the page is left.
- Layouts are saved on the server per user (per device type on the device page); administrators can push a template. The dashboard keeps its own order/custom/sizes but uses the same kit.

## Checklist for a new page
1. Screenshot at 820, 1400 and 3440 px (see `docs/` or memory: playwright with a bearer token) and look for empty space, sideways scroll, stretched buttons.
2. Count the Save buttons (one). Check the colours.
3. Link every problem it shows to where it can be fixed; link its settings from the page.
4. Add a changelog line.
