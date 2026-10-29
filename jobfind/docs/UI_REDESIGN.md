# FindAll interface and workspace cleanup — 2026-10-12

The native Rust/egui application now uses grouped navigation, a compact menu at
smaller widths, a fixed status footer, separate scrolling positions for each
section, and one graphite/amber design without a theme switch. Palette,
typography and shared dimensions live in `rust-ui/src/theme.rs`. Existing
collector, credential and email-confirmation behavior is retained.

The application opens through the parent `start.bat` or the existing project
launcher. Tests moved to `tests/`, the integration audit to `docs/`, and parent
research documents and examples to their own folders. Installation commands
retain their existing paths. Legacy executable and diagnostic HTML are archived.
The moves are recorded with original and current SHA-256 values in
`../../_archive/project-cleanup-20261012-130854/moves.csv`; originals of edited
files and the previous installed executable are stored alongside it.

## Current verification after simplifying the design

- Removed the theme toggle, the light palette and the light render option.
- Rebuilt and replaced the installed `findall-ui.exe`; the previous executable
  is retained in `jobfind_out/single-design-check-20261012-160406/`.
- Full `test.bat`: 213 Python tests, 12 Rust tests and the existing module
  self-checks passed. Theme contrast and forcing the product appearance when
  the context initially requests light mode are covered.
- All eight pages rendered at normal size and at 900×680 with 150% zoom:
  16 native screenshots reviewed, each using the same design, with no horizontal
  overflow above rounding tolerance. Long forms scroll vertically.
- `cargo fmt --check`, release build and `pip check` passed.
- A new native keyboard-triggered `Python backend` search returned 8 jobs and
  4 GitHub projects. CSV counts match the UI; all 8 retained jobs match the
  full query in the saved database and have source URLs. Database integrity is
  `ok`. Empty job/history queries show actionable validation without starting
  a task.
- The updated UI reopened the saved Russian query `Анна Ахматова`: 29 results,
  also confirmed through a separate read-only CLI history readback.
- Installed/release EXE SHA-256:
  `0FED8DCCD94ECE2F5B064FD4B985DFB28B28C32DB0C05F120A6DE4A3493E3A7F`.
- The two working databases, profile and saved network state retain their hashes.

Evidence: `jobfind_out/single-design-check-20261012-160406/`.

## Initial verification before simplifying the design

- Python unittest discovery from the new `tests/` directory: 189 tests passed.
- GitHub Email Hunter attribution self-check: passed separately.
- Rust: 11 tests passed, including palette contrast, widget states and page routing.
- `cargo fmt --check` and release build: passed.
- Native renders: all eight pages, light/dark, normal 1240×820 and minimum
  900×680 with 150% egui zoom: 32 screenshots saved. Horizontal overflow stayed
  below one logical point (rounding tolerance); growing content scrolls vertically.
- Expanded Research settings: captured and inspected in both themes.
- One fictional archive row and one fictional telemetry row imported in separate
  disposable result folders: both light/dark native runs passed. Archive providers
  and local wireless discovery were disabled for these runs.
- Root launcher: produced an isolated native screenshot successfully.
- Installed EXE matches the Cargo release binary:
  `42AD325363FC98BF6808F6843819B2EF0FF5D2CB1EE28295BAA0FA934CFDE0BD`.
- Existing parent/project databases, profile and saved network state retained
  their original hashes. Existing output directories remain in place.

Evidence: `jobfind_out/design-review-20261012/` in this project. The render matrix
and Python test log are saved there. Screenshots were reviewed for text contrast,
selected controls, form alignment and overflow. Font data comes from Windows
Segoe UI with the existing egui fallback; no new dependency was added.

## Limits

This is a native egui UI: HTML/CSS token lint, axe, Playwright state verification
and browser accuracy-report scripts do not apply. The native palette tests and
renderer checks above were used instead. No WCAG certification is claimed;
screen-reader operation, a full manual keyboard pass, forced colors and RTL were
not verified. Animations are disabled in the shared style. The current application
uses one fixed product design when opened, regardless of the system theme.

Live external APIs, authenticated AI providers, radio hardware, sending email,
dependency installation and publication were not exercised by this redesign.
Generated caches and installed environments are retained; archiving files did
not aim to reduce disk usage.

A subsequent functional check exercised native UI actions, live Codex,
GitHub, Arbeitnow and archive sources, and saved exports. See
[functional verification](FUNCTIONAL_CHECK_20261012.md) for results and limits.
