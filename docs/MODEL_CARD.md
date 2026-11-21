# SentinelAI model card

| Field | Baseline |
| --- | --- |
| Distribution | Optional approved model bundles |
| Classifier | Per-format binary LightGBM |
| Rich feature schemas | `pe-ember-static-v2` and `elf-ember-static-v2`, available in 0.1.2 |
| Histogram schemas | `pe-ember-histogram-v1` and `elf-ember-histogram-v1` |
| Custom ELF schema | `elf-static-v1` |
| Score | Monotonic Platt calibration fitted on held-out validation data |
| Attribution | LightGBM TreeSHAP in raw log-odds, before calibration |
| Optional anomaly score | Isolation Forest percentile against held-out benign validation features |
| Behavioral classification | Unavailable. Import produces descriptive counts and category sequences. |

Use scores for analyst triage. A high score means the classifier found patterns associated
with a positive label in its training data. A low score can miss malware, and a benign
file can score high. TreeSHAP attributes the raw model score to features under the fitted
model. A contribution describes a statistical relationship rather than the cause or intent
of any behavior. The anomaly percentile increases review priority when very high, while
preserving the calibrated classifier score and its threshold decision. Percentage values
are conditional on the calibration data. They are not guarantees for arbitrary system files.

An approved bundle includes schema version, versions of software and data, provenance,
split descriptions, distinct class counts, threshold, calibrator coefficients, Brier
score, precision, recall, F1, ROC-AUC, false-positive rate, and a held-out confusion
matrix in TN/FP, FN/TP order. Model Insights reports the values from the installed
bundle. The 0.1.1 release targeted a 1% false-positive rate on calibration data.
The 0.1.2 candidates target maximum calibration accuracy and require at least 94%
accuracy on the later benchmark set for promotion. Test performance comes from later periods in the
publishers' official datasets. Accuracy on a specific deployment population requires
representative data from that environment.

## Release 0.1.2 benchmark results

| Model | Test records | Accuracy | Recall | False-positive rate | Precision | ROC-AUC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| PE (`pe-ember2018-002`) | 199,939 | 94.61% | 96.25% | 7.02% | 93.20% | 0.9886 |
| ELF (`elf-ember2024-002`) | 5,988 | 94.21% | 95.87% | 7.46% | 92.80% | 0.9831 |

The test confusion matrices are `[[92960, 7022], [3748, 96209]]` for PE and
`[[2766, 223], [124, 2875]]` for ELF. Both models exceeded the 94% promotion gate.
The cutoffs improve recall and raise the rate of false alerts compared with the 0.1.1
release. The two benchmarks use different source populations and dates. The evaluation
reuses the publishers' later test partitions from the 0.1.1 comparison. Training,
early stopping, calibration, and threshold selection used the earlier training and
validation records. Accuracy includes both classes and depends on their prevalence.
[Dataset provenance and reproduction](DATASETS.md)

## Low false-positive retraining

The precision candidates used expanded static features and training selected by
validation recall at low false-positive rates. The primary cutoff used a 0.8%
validation false-positive budget. The later test set was used to measure the outcome.
Promotion requires accuracy and recall above the corresponding 0.1.2 benchmark and
a later false-positive rate strictly below 2%.

| Windows PE model and cutoff | Test accuracy | Malware recall | False-positive rate |
| --- | ---: | ---: | ---: |
| Precision fit (`pe-ember2018-003`), 0.8% validation budget | 95.44% | 91.80% | 0.92% |
| Same fit, 1.5% validation budget | 96.54% | 94.67% | 1.60% |

Both PE rows use the same 199,939 later records as the 0.1.2 PE benchmark.
The strict cutoff produced 924 false positives and 8,199 missed malware records.
The 1.5% validation cutoff produced 1,603 false positives and 5,324 missed malware
records. Both improved accuracy and reduced false positives relative to the 0.1.2
cutoff. Both fell below its recall, and the candidate failed the promotion gate.

| ELF model and cutoff | Test accuracy | Malware recall | False-positive rate |
| --- | ---: | ---: | ---: |
| 0.1.2 model evaluated at the 0.8% validation budget | 93.85% | 89.23% | 1.51% |
| First precision fit (`elf-ember2024-003`), 0.8% validation budget | 94.82% | 91.16% | 1.51% |
| Validation-selected fit (`elf-ember2024-004`), 0.8% validation budget | 95.04% | 91.70% | 1.61% |
| Validation-selected fit, 1.5% validation budget | 95.42% | 93.63% | 2.78% |
| Validation-selected fit, stricter 0.4% validation budget | 92.22% | 85.53% | 1.07% |

Each ELF row uses 5,988 later records. The first precision fit caught 58 more
malware records than the 0.1.2 model at the same 0.8% validation false-positive
budget. Each produced 45 false positives. The validation-selected fit produced
48 false positives and 249 missed malware records. It improved accuracy and
reduced false positives compared with the deployed 0.1.2 cutoff, and its recall
fell below the promotion minimum. ELF feature archives contain byte and string
statistics, so these fits did not learn native ELF header or section features.
[EMBER2024 benchmark paper](https://arxiv.org/abs/2506.05074)

These experiments evaluated the classifier's elevated-score decisions. Neither
candidate was promoted to a release bundle.

## Release 0.1.1 benchmark results

| Model | Later test records | ROC-AUC | Precision | Recall | False-positive rate | F1 | Brier score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PE (`pe-ember2018-001`) | 199,928 | 0.9006 | 94.70% | 22.86% | 1.28% | 0.3683 | 0.1501 |
| ELF (`elf-ember2024-001`) | 5,988 | 0.9732 | 97.80% | 82.89% | 1.87% | 0.8973 | 0.0641 |

The confusion matrices are `[[98703, 1278], [77099, 22848]]` for PE and
`[[2933, 56], [513, 2486]]` for ELF. The PE baseline missed most labeled malicious
files at the selected alert threshold. Use it as a supplementary triage signal.
The PE and ELF test records come from different collections and time periods.
[Dataset provenance and reproduction](DATASETS.md)

The 0.1.1 models use file size and normalized byte counts. The 0.1.2 models add
local entropy and printable string features, plus structural fields for PE.
Unrelated executables can have similar features. Prevalence shift, temporal drift, compiler and packing changes, labeling
errors, and undersampled distributions limit generalization. A workflow using a model
should pick a threshold in advance and measure false positives on a representative benign
set as well as recall, with extra evaluation across sources and across time.

[LightGBM TreeSHAP documentation](https://lightgbm.readthedocs.io/en/stable/Features.html#tree-shap)
