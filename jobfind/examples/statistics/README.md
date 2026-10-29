# Working statistics examples

Open **Workspace → Statistics → Choose file**, select one JSON file here, and
press **Analyze data**. **Models and input guide** also opens this folder.
These are fictional inputs, not observations about real people or equipment.

- bert-umap.json: local multilingual sentence-BERT and UMAP projections.
- lstm-activity.json: a 180-hour activity series with a late synthetic spike.
- kriging-field.json: nine measured field values in a small geographic area.
- triangulation-bearings.json: true-north bearings with 0.5 degree one-sigma errors.
- multilateration-ranges.json: distances with five metre one-sigma errors.

Both geometric examples point to the known synthetic coordinate **0.01, 0.01**.
Change observations/errors only when you have measured replacements. The output
ellipse is conditional on the supplied errors and spherical-Earth assumptions.
Model installation downloads the pinned public BERT weights once; subsequent
analysis stays local. Run setup-analysis.bat if dependencies/model are missing.
