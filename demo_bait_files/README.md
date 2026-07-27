# Demo bait files — synthetic, not real data

Everything in this folder is **fabricated test fixture data**, used to demo the
FILE-monitoring agent (`run_agents.py`) and keyword-based detection
(`app/models/ml_model.py`'s `KeywordDetector`) catching access to
"sensitive-looking" files.

None of the names, salaries, or credentials here are real:

- `passwords.txt` uses AWS's own publicly documented example access key
  (`AKIAIOSFODNN7EXAMPLE`, from AWS's official docs) and Stripe's literal
  `sk_live_...Example...` test key format — not working credentials.
- `confidential_salaries.txt` / `confidential_financials.doc` /
  `customer_data.xlsx` use generic placeholder names (e.g. "John Anderson,
  CEO") with made-up numbers, not any real company or person.

Point the FILE monitoring agent at this folder (or drop a copy on your
Desktop/Documents) to see the detection engine flag access to files whose
names or content match the suspicious-keyword list (`confidential`,
`password`, `salary`, etc.) in `config/config.py`.
