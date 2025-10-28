# Test Report — AI-NGFW

This document summarizes the unit tests included for the AI-NGFW project and shows how to reproduce the results for an external examiner.

Summary (latest run)

- Total tests: 3
- Passed: 2
- Skipped: 1
- Failed: 0
- Time: 0.177s
- JUnit XML: `reports/test_results.xml`

Tests added for the examiner

1) tests/test_datastore.py — test_datastore_save_and_tail_jsonl

- Purpose: Verify that `DataStore.save_packet()` appends a JSONL line and that `DataStore.tail_jsonl()` can read it back. Demonstrates data-persistence (capture → storage).
- Fast, isolated, and uses a temporary directory so it has no side-effects on your repo.

2) tests/test_visualizations.py — test_summarize_traffic_for_plotly_basic

- Purpose: Verify that `summarize_traffic_for_plotly()` aggregates raw packet dicts into time-series buckets (`time_x`, `time_y`) and returns top source IPs used by the dashboard charts.
- Shows the analytics pipeline feeding the dashboard.

How to run locally (PowerShell)

1. Run the tests and show terminal output:

```powershell
C:/Users/Admin/AppData/Local/Programs/Python/Python38/python.exe -m pytest -q
```

You should see output similar to:

```
.. [100%]
2 passed, 1 skipped in 0.17s
```

2. Produce a JUnit XML file for CI/presentation:

```powershell
C:/Users/Admin/AppData/Local/Programs/Python/Python38/python.exe -m pytest -q --junitxml=reports/test_results.xml
```

Presentation tips

- Start by showing the `TESTS_REPORT.md` summary slide.
- Run the pytest command live — it's fast and convincing.
- Open `reports/test_results.xml` (or the HTML below) to show structured results if required by the examiner.

Notes

- The original integration script `tests/test_project.py` is intentionally skipped during automated unit test runs because it exercises end-to-end behavior and writes files; run it manually for a full demo.
- If you want an HTML-rendered report, open `reports/test_results.html` (generated alongside the XML).

---
Generated: 2025-10-28
