---
name: data-analysis
description: >-
  Data science, statistical analysis, exploratory data analysis, and Jupyter notebook (.ipynb) verification
  discipline: row-count and drop accounting, train/test split anti-leakage, baseline-first modeling, clean
  top-to-bottom execution, and honest chart scaling. Invoke with /data-analysis or when analyzing datasets,
  building notebooks, running statistical tests, or generating analytical charts ("veri analizi", "veri bilimi",
  "istatistiksel analiz", "veri sızıntısı", "notebook"). Not for database schema migrations (use
  'database-migrations') or general unit test authoring (use 'test-design').
---

# Data Analysis: Reproducible Pipelines, Anti-Leakage, and Honest Reporting

Analytical scripts, statistical reports, and interactive notebooks fail silently: a script can exit with code `0` while dropping half the dataset via an unlogged join, leaking future test targets into feature normalization, relying on deleted out-of-order notebook cells, or plotting a truncated axis that exaggerates noise. This skill enforces deterministic accounting and methodological rigor across data workflows.

## 1. Explicit Shape & Drop Accounting (Zero Silent Row Loss)

Silent row or column loss invalidates downstream statistics:

- **Log Initial and Final Shapes:** Print and record initial row count, column count, date/time span, and primary key uniqueness before any filtering or joining.
- **Account for Every Dropped Row:** Before and after every `dropna`, inner join, deduplication, or outlier filter, record the exact number and percentage of removed rows and the reason they were excluded. Never apply `.dropna()` across an entire dataframe without specifying target columns and reporting the drop count.
- **Join Cardinality Verification:** Assert expected join cardinality (`one-to-one`, `many-to-one`) explicitly before merging tables so duplicate keys do not silently multiply rows and inflate sums.
- **Missing-Data Mechanism Check:** State whether missing values are missing at random or systematically tied to a cohort, timestamp, or sensor failure before imputing them.

## 2. Anti-Leakage & Split Invariant

Target leakage produces high validation scores that collapse in production:

- **Split Before Any Fit:** Partition datasets into training, validation, and test splits *before* computing imputation statistics (mean, median), feature scaling (`StandardScaler`, min-max), target encodings, vocabulary dictionaries, or feature selection. Fit transformers exclusively on the training split and apply `.transform()` to validation and test splits.
- **Respect Temporal and Entity Boundaries:**
  - *Time-series data:* Use chronological splits or rolling-origin evaluation; never shuffle future observations into the training set.
  - *Grouped or user-level data:* Group all records belonging to the same entity, user, or session into the same split so entity memorization cannot masquerade as generalization.
- **Feature Availability Audit:** Verify that every feature used at prediction time is actually recorded *at or before* the prediction timestamp in production, not backfilled after the outcome occurs.

## 3. Baseline First & Statistical Honesty

- **Trivial Baseline Before Complexity:** Before training a complex model or deep pipeline, evaluate a deterministic heuristic (mean, median, last-seen value, majority class, or single-feature linear model) on the exact same split and metric. Report complex model gains strictly as a delta against that baseline (`skills/harness/SKILL.md` §1 Efficiency Ladder).
- **Metric Alignment with Class Balance:** Never report raw accuracy alone on imbalanced datasets; pair precision, recall, calibration, or cost-weighted metrics with confusion counts.
- **Effect Size and Uncertainty:** When reporting statistical comparisons or hypothesis tests, always pair p-values with the concrete effect size, sample size (`n`), and confidence interval or spread (standard deviation or interquartile range). Separate observed correlation from causal claims (`GEMINI.md` Rule 8).

## 4. Notebook (`.ipynb`) Reproducibility & Code Hygiene

- **Clean Top-to-Bottom Execution:** Every notebook must run cleanly from cell 1 to the final cell in a fresh process (`jupyter nbconvert --to notebook --execute` or script equivalent) with monotonically increasing execution counts (`1..N`) and zero hidden state from deleted or out-of-order cells.
- **Pin Seeds and Environment:** Set explicit random seeds at the top of the notebook or script and read dependency versions from the lockfile (`skills/harness/SKILL.md` §2).
- **Extract Reusable Logic:** When a transformation or plotting helper is reused across 3 or more cells (`skills/harness/SKILL.md` §1), extract it into a pure Python module and cover its edge cases (`NaN`, empty input, single-row input, duplicate keys) with unit tests (`skills/test-design/SKILL.md`).

## 5. Honest Charting & Render-and-Inspect Gate

- **Truthful Axes and Labels:** Bar charts must start at a zero baseline. Every chart must state the unit of measurement on both axes, the sample size (`n = ...`), and the time window or cohort shown.
- **Render-and-Inspect (`skills/harness/SKILL.md` §3B Step 4b):** After generating any chart image (`.png`, `.svg`) or tabular report (`.pdf`, `.html`, `.csv`), inspect the output via `read_file` or a summary check to confirm labels are not clipped, legends do not overlap data points, and plotted numbers match the computed summary table.

## 6. Delivery Checklist

Before delivering a data analysis, model evaluation, or notebook, verify:
- [ ] Initial and final row/column counts and every filter/join/null-drop count are explicitly reported.
- [ ] All statistics, imputers, scalers, and encoders were fit strictly after splitting (respecting temporal and entity boundaries).
- [ ] Model or pipeline results are compared against a simple deterministic baseline on the same split.
- [ ] Notebooks or scripts execute cleanly top-to-bottom from a fresh state with zero out-of-order cell dependencies.
- [ ] Generated charts include units, sample sizes (`n`), non-deceptive baselines, and passed visual inspection via `read_file`.
