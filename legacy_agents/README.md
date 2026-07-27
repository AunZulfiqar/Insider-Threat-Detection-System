# Legacy agent scripts — superseded, do not run

These five scripts are the original standalone monitoring agents. They've
been replaced by **`run_agents.py`** in the project root, which runs all
four monitors (EMAIL, FILE, HTTP, USB) in one process with fixes for bugs
that are still present here:

- `agent_HTTP.py` / `monitor.py` — Chrome/Edge timestamp filtering uses Unix
  epoch microseconds instead of the WebKit epoch (seconds since 1601-01-01),
  so the "recent URLs" query never matches anything real.
- `agent_USB.py` — sends activity `"COPY_TO_USB"`, which the detection
  engine's feature schema doesn't recognize (it expects `"Connect"`).
- All of them — `USER_ID` is hardcoded to `"AUN001"` instead of the actual
  Windows username, so events land under the wrong user in the dashboard.

Kept here for reference only. Use `python run_agents.py` from the project
root instead.
