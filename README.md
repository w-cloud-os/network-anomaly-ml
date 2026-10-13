# Network Anomaly Detection

Ranks the most suspicious hosts from network flow records and shows why each one is on the list.

Built on one day of the CIC-IDS2017 dataset (Friday afternoon, PortScan). The goal is a short, explainable list for an analyst to review, not a headline accuracy number.

## Data

- File: `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` (TrafficLabelling version, which includes IP addresses). Place it in `data/` (gitignored).
- 286,467 flows, 85 columns. 158,930 flows are labeled PortScan (55.5%) and 127,537 are benign.
- 3,667 distinct source IPs. All attack flows come from one address, `172.16.0.1`.

## Method

1. **Unit of analysis: host-window.** Flows are grouped by source IP and 5-minute window, giving 7,965 rows. A window is labeled an attack if it contains any attack flow. This gives 12 positive windows (0.15%), which is much closer to a realistic base rate than the 55% at flow level.
2. **Features per window:** flow count, distinct destination ports, distinct destination IPs, mean forward and backward packets, mean flow duration, fraction of flows with no reply, plus ratios of these. Features are log-scaled and standardized. The label is never a feature, and neither is the source IP.
3. **Models:**
   - Baselines: rank by flow count, rank by distinct destination ports.
   - Logistic regression (class-weighted, L2-regularized), evaluated with a time-based split in both directions.
   - Isolation Forest (unsupervised, labels used only to check the ranking afterwards).
4. **Metrics:** precision@k and recall@k on the ranking. Accuracy is not reported, because it is uninformative at this base rate.
5. **Explanations:** for each flagged window, the two features with the largest standardized deviation from the typical window.

## Why precision is low at the top of the list

If 1 in 1,000 hosts is compromised and a detector catches 90% of them but flags 2% of clean hosts, then P(compromised | flagged) = 0.9 × 0.001 / (0.9 × 0.001 + 0.02 × 0.999) ≈ 4.3%. About 96% of flags are false alarms even though the detector looks good. In this data the host-level base rate is 1 attacker in 3,667 hosts (0.027%), so false alarms dominate any top-k list.

## Results

All 12 positive windows are genuine: each has an attack-flow fraction of about 1.0. Five are loud scans (about 1,000 distinct ports, 2,011 to 93,097 flows). Seven are quiet (1 to 5 ports, 1 to 177 flows).

| Method | Window-level result | Host-level rank of attacker |
|---|---|---|
| Rank by flow count | P@5 = 0.8, R@12 = 0.42 | 1 of 3,667 |
| Rank by distinct ports | P@5 = 1.0, R@12 = 0.42 | 1 of 3,667 |
| Logistic regression, 4 features, C = 0.1 | train early / test late: attack ranks 2, 3, 4, 5, 7, 972 of 3,574; train late / test early: 87, 87, 1207, 1862, 1883, 1893 of 4,391 | not computed |
| Isolation Forest | loud scans ranked 9, 21, 31, 40, 41 of 7,965; quiet scans ranked 436 to 1,005 | 6 of 3,667 |

Isolation Forest top-20 host list: 1 attacker, 13 internal `192.168.10.x` workstations, 6 external addresses. That is 5% precision, roughly 180 times the random rate, with 19 hosts to review for each real one.

## Findings

- The loud scan is easy: a single feature (distinct destination ports) ranks it first among all hosts. Models add little on this file.
- The seven quiet scans are not reliably detectable from flow summaries. Logistic regression found some of them in one split and not the other, and with 6 positives per training set the coefficients are unstable.
- Isolation Forest flags unusual hosts, not malicious ones. Busy workstations that contact 50 to 350 machines in five minutes rank above the attacker.
- The explanation view separates three patterns: many ports on one target (scan-like), many targets on few ports (fan-out), and long or heavy transfers. An analyst can triage the list quickly.
- **The victim looks like a scanner.** `192.168.10.50` ranks 4th in the list. In its 02:50 window, 488 of its 560 outbound flows go to `172.16.0.1`, and 93,096 of its 93,169 inbound flows are PortScan flows from `172.16.0.1`. Its destination ports are mostly high numbers, which suggests reply traffic to the scanner's source ports. Host-level features that ignore direction flag the target alongside the source.

## Limitations

- One day, one attack type, one attacker host. Host-level results are a single data point, and nothing here shows the approach transfers to other attacks.
- `172.16.0.1` is probably a gateway or NAT address in the lab setup, so the label partly reflects the dataset's design.
- The benchmark is far richer in attacks than a real network at flow level (55.5% vs. realistic fractions below 1%). Window-level labeling brings it closer, but precision here still overstates production precision.
- Several model variants were compared while looking at test results, and each test set holds only 6 positives. Treat the ranks as exploratory, not as final performance.
- Timestamps in the file have no AM/PM marker, so the clock values (01:00 to 03:29) do not match the afternoon capture. Window boundaries are unaffected.
- A window with a single attack flow cannot be distinguished from quiet normal traffic using these features.

## Recommendations

- Score each host against its own history or peer group (workstations vs. servers) instead of against all hosts. This is the most likely way to cut the workstation false alarms. Untested here, because the data covers only a few hours.
- Add direction-aware features, such as inbound versus outbound flow ratios and reply-flow filtering, so that targets are not flagged as sources. When a flagged host's top peer is also flagged, report the pair.
- Evaluate on additional days and attack types before trusting any model.

## Reproduce

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
jupyter notebook   # run notebooks/01_explore.ipynb
```
