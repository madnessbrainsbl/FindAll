# Statistical analysis in FindAll

The supplied OSINT article describes a family of analytical techniques and external
datasets, not one installable tool. The previous product had collection, evidence
graphs, timelines, quality checks and exports; it did not have the statistical
calculations below. These calculations now run locally through **Workspace →
Statistics**, or **Dossier → Statistical analysis** for the current saved report.
Choose a dataset and press **Analyze data**. **View dossier / AI / diagram**
loads the new result into the existing Research workflow. Analysis creates a new dossier;
the selected input, previous reports and user database remain unchanged.

## Implemented methods

| Article capability | Product behavior / prerequisites |
| --- | --- |
| Mean, median, modes, variance, SD, quartiles | Numeric fields; sample variance/SD; missing values are counted, never changed to zero. IQR outlier references retained. |
| Pareto / Zipf | Exploratory positive-tail Pareto MLE and actor rank-frequency diagnostic; does not certify a power-law distribution. |
| Financial/registry numeric correlation | Pairwise complete records, Pearson and Spearman; at least eight pairs, constant fields excluded. Pearson p-values and Benjamini–Hochberg q-values retain the independence assumption. It does not fetch financial registries or establish causation. |
| Behavioral activity | Explicit event dates, bounded common UTC bins, actor activity correlations, UTC-hour counts and inter-event interval coefficient of variation. Collection timestamps are excluded; no bot verdict. |
| Temporal anomalies | Two-sided CUSUM, k=0.5, h=5, baseline from the first quarter (at least four bins); at least sixteen bins. Signals are review candidates. |
| Temporal decomposition and scenarios | Robust STL after two user-specified periods; converged ARIMA(1,0,0) after 24 varying bins, five-bin forecasts and 95% model intervals. No validated threat forecast or automatic policy decision. |
| Graph communities / hubs | Seeded Louvain, modularity, degree centrality, sampled betweenness, PageRank; first Girvan–Newman split only below 80 nodes/200 edges. Imported labels are dataset-scoped candidates, never global identities. |
| Lexical similarity | TF-IDF unigrams/bigrams, at most 5,000 terms; cosine >=0.8 pairs reference source records. This is not an authorship/AI-text detector. |
| Geographic clustering | WGS84/haversine DBSCAN, min_samples=3, radius 5 km by default; noise stays explicit. Zero coordinates are valid, missing/invalid coordinates excluded. |
| Spatial density / autocorrelation | Relative spherical KDE scores at observed points; Moran I for eight located measured `value` records, symmetric five-nearest-neighbour weights, 99 seeded permutations. No invented coordinates or independent geolocation proof. |
| Multivariate anomalies / dimensionality | Standardized complete-case numeric matrix; seeded Isolation Forest, PCA and t-SNE. No imputation; at least eight records, t-SNE at least twelve and two varying fields. |
| BERT semantic embeddings | Real local BertModel, pretrained multilingual sentence-transformer, 384 dimensions, attention-mask mean pooling, 128 tokens/text, up to 300 documents. SHA-256 verified safetensors; no remote model code or text uploads. |
| LSTM autoencoder | Actual LSTM encoder/decoder trained on observed bin counts: 12-bin windows, eight hidden units, forty epochs. Chronological 60/20/20 train/calibration/test partitions without crossing windows; train-only normalization, calibration 99th-percentile threshold, holdout MSE and safe exported weights. Requires 120 bins with a varying training prefix. |
| UMAP | Seeded two-dimensional numeric and BERT embedding projections with source record references. Up to 500 complete numeric records / 300 texts; constant/duplicate-only vectors are insufficient, not invented clusters. Native hoverable scatter plots. |
| Kriging | Actual OrdinaryKriging with fitted spherical variogram, local spherical azimuthal-equidistant coordinates, six distinct measurements, at most 200 locations within 250 km of the centre. Duplicate-location values are averaged; a 16x16 grid is clipped to the measured convex hull. Predictions and model variances are exported. |
| Triangulation / multilateration | Weighted bearing/range fit for explicit target labels, three distinct calibrated observers, spherical distances/true-north bearings, multiple starting points, residual checks and a conditional 95% error ellipse. Parallel/ambiguous geometry is rejected; inconsistent measurements are partial. Observer radius <=50 km, solution radius <=100 km. |
| Supervised ML | Random Forest and gradient boosting with a stratified 70/30 holdout when `label` has at least two classes, forty rows total and ten examples per class. Balanced accuracy/feature importance are sample evaluation, not externally validated attribution. Models are never loaded from pickle. |
| Customer report / reproducibility | English HTML tables, activity SVG, source record references; Markdown, full JSON calculations, dossier CSV, input/calculation SHA-256, versions, seed, parameters, source states and limitations. AI evidence marks calculation summaries as interpretations; graph calculation edges are interpretations. |

Methods run only with suitable data. Their actual outcome is `ok`,
`insufficient_data`, `unavailable` or `error`; insufficient samples are not
reported as successful analyses. Missing dependencies can be installed with
`setup-analysis.bat` and are also included in normal `setup.bat` requirements.

## Input and bounds

CSV/TSV, a JSON array, JSONL, `{ "records": [...] }`, or a saved FindAll dossier.
Fields are optional: `id`/`event_id`, `actor`/`username`/`author`, ISO-8601
`timestamp`/`published_at`/`created_at`/`date`, `text`, `source`, `source_url`,
`latitude`, `longitude`, numeric `value`/other measurement columns or a `metrics`
object. `relation_source` and `relation_target` provide explicit graph edges;
`source`/`target` edge lists are also accepted. `label` enables supervised checks.
Naive event dates explicitly use UTC. Ordinary `observed_at` is collection time;
wireless telemetry observation time is the narrow exception.

Input is limited to 40 MB / 5,000 retained observations / 24 numeric fields.
Correlation uses at most 24 fields; time analysis keeps at most 512 bins and
forty actors; text uses 500 documents; spatial/multivariate analysis uses at most
1,000 observations; t-SNE uses 300; graphs use 600 nodes / 1,500 edges. Bounds,
failed rows, invalid dates/coordinates and deduplication are recorded. Counts
for omitted CSV rows are lower bounds when reading stops at the limit.
The HTML report shows bounded tables; full retained references are in JSON.

```powershell
.venv\Scripts\python.exe jobfind.py statistics --path "C:\Cases\events.csv"
.venv\Scripts\python.exe jobfind.py statistics --path "C:\Cases\dossier.json" --radius 2 --period 12
```

Analysis makes no network requests or model uploads, performs no automated
hardware discovery and does not mutate the input. BERT installation is a separate
explicit download. Existing configured AI analysis remains a separate explicit action.
Open-data exports from statistical agencies, World Bank, registries or permitted
platform APIs can be imported; this is not a claim that all those API accounts
and collection connectors are configured or working.

## Models, measurements and examples

The BERT bundle is `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`,
pinned revision `e8f8c211226b894fcb81acc59f3b34ba3efd5f42` (Apache-2.0).
`third_party/models/multilingual-minilm/findall-model.json` retains per-file hashes;
weight SHA-256 is `eaa086f0ffee582aeb45b36e34cdd1fe2d6de2bef61f8a559a1bbc9bd955917b`.
The upstream model card is retained. `setup-analysis.bat` installs dependencies
and downloads the model; **Models and input guide → Install / repair BERT model**
does the same explicit model download from the native UI. CLI:
`jobfind.py statistics --install-model`. Normal analysis loads only these local
safetensors/config/tokenizer files with remote code disabled. Keep the model
folder beside the product; copying only the EXE does not include the model.

**Open example datasets** in the same UI guide opens `examples/statistics/`:

- `bert-umap.json`: multilingual texts and numeric feature examples.
- `lstm-activity.json`: 180 hourly bins, varying baseline and later activity spike.
- `kriging-field.json`: nine located field measurements.
- `triangulation-bearings.json`: four true-north bearings towards the known
  synthetic point 0.01 latitude / 0.01 longitude.
- `multilateration-ranges.json`: four ranges towards that same synthetic point.

For triangulation, supply `target_id`, `observer_latitude`, `observer_longitude`,
and `bearing_deg` (0 inclusive to 360 exclusive) plus `bearing_error_deg` (>0),
or `range_m` (>0) plus `range_error_m` (>0). Flat CSV columns and a JSON
`measurement` object are supported. Errors are supplied one-sigma calibration
uncertainties; the program does not invent them. Independent Gaussian errors,
spherical Earth and correctly calibrated true-north directions are explicit
model assumptions. Inconsistent/ambiguous observations must be reviewed.
Directions measured from landmarks or imagery must already be calibrated;
raw shadow pixels or an uncalibrated star image are not bearing measurements.

## Interpretation boundary

This is a bounded exploratory analysis workflow, not an installation of R,
Maltego, Gephi, Power BI or Tableau. Existing FindAll graph and report tools are
reused. The five advanced methods above are real implementations and participate
in the same native screen, dossier, AI evidence and exports. They do not turn
sample similarities/anomalies into validated authorship, sentiment or AI-content
detectors. Terabyte-scale indexing,
automatic social-network botnet attribution and validated threat prediction are
not claimed. Source coverage bias and correlated observations remain limitations.

Algorithm references: [DBSCAN](https://scikit-learn.org/stable/modules/generated/sklearn.cluster.DBSCAN.html),
[Louvain](https://networkx.org/documentation/stable/reference/algorithms/generated/networkx.algorithms.community.louvain.louvain_communities.html),
[ARIMA](https://www.statsmodels.org/stable/generated/statsmodels.tsa.arima.model.ARIMA.html).
Advanced references: [BERT model and pooling](https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2),
[PyTorch LSTM](https://docs.pytorch.org/docs/stable/generated/torch.nn.LSTM.html),
[UMAP](https://umap-learn.readthedocs.io/en/latest/api.html),
[PyKrige](https://geostat-framework.readthedocs.io/projects/pykrige/en/stable/generated/pykrige.ok.OrdinaryKriging.html).
