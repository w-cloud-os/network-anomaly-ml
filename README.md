# Network Anomaly Detection

Ranks the most suspicious hosts from network flow records and shows why each one is on the list.

Built on two days of the CIC-IDS2017 dataset: Friday afternoon (port scan) and Wednesday (denial-of-service). The goal is a short, explainable list for an analyst to review, not a headline accuracy number. The second day tests whether anything learned on the first one carries over.

## Repository layout

```
data/        raw CSVs (gitignored)
notebooks/   01_explore (first day, step by step), 02_friday_replay (reproduces it using src/),
             03_wednesday_dos (second day and transfer test)
src/         data.py, features.py, models.py, evaluate.py, explain.py
```

## Data

| | Friday | Wednesday |
|---|---|---|
| File | `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | `Wednesday-workingHours.pcap_ISCX.csv` |
| Flows | 286,467 | 692,703 |
| Attack labels | PortScan (158,930 flows) | DoS Hulk 231,073; GoldenEye 10,293; slowloris 5,796; Slowhttptest 5,499; Heartbleed 11 |
| Attack source | `172.16.0.1` | `172.16.0.1` (252,672 attack flows) |
| Attack target | `192.168.10.50` | `192.168.10.50` (port 80, 252,661 flows) and `192.168.10.51` (port 444, 11 flows) |

Both files are the TrafficLabelling version, which includes IP addresses. Place them in `data/`.

## Method

1. **Unit of analysis: host-window.** Flows are grouped by source IP and 5-minute window. A window is labeled an attack if it contains any attack flow. Friday gives 7,965 windows (12 positive, 0.15%) and Wednesday gives 25,626 windows (27 positive, 0.11%). Flow-level, Friday is 55.5% attacks, which is far from realistic. Window-level is much closer.
2. **Features per window:** flow count, distinct destination ports, distinct destination IPs, mean forward and backward packets, mean flow duration, fraction of flows with no reply, and ratios of these. Features are log-scaled and standardized. The label and the source IP are never used as features.
3. **Methods:** single-feature rankings (flow count, distinct ports, distinct IPs), logistic regression (class-weighted, L2-regularized), and Isolation Forest (unsupervised).
4. **Metrics:** precision@k and recall@k on the ranking, plus the rank of the attacker host. Accuracy is not reported, because it is uninformative at this base rate.
5. **Explanations:** for each flagged window, the two features with the largest standardized deviation from the typical window.

## Why precision is low at the top of the list

If 1 in 1,000 hosts is compromised and a detector catches 90% of them but flags 2% of clean hosts, then P(compromised | flagged) = 0.9 × 0.001 / (0.9 × 0.001 + 0.02 × 0.999) ≈ 4.3%. About 96% of flags are false alarms even though the detector looks good. Here the host-level base rate is 1 attacker in 3,667 hosts on Friday and 1 in 7,689 on Wednesday, so false alarms dominate any top-k list.

## Results: Friday (port scan)

All 12 positive windows are genuine, each with an attack-flow fraction of about 1.0. Five are loud scans (about 1,000 distinct ports, 2,011 to 93,097 flows). Seven are quiet (1 to 5 ports, 1 to 177 flows).

| Method | Window-level result | Attacker host rank |
|---|---|---|
| Rank by flow count | P@5 = 0.8, R@12 = 0.42 | 1 of 3,667 |
| Rank by distinct ports | P@5 = 1.0, R@12 = 0.42 | 1 of 3,667 |
| Logistic regression (4 features, C = 0.1) | train early / test late: attack ranks 2, 3, 4, 5, 7, 972 of 3,574; train late / test early: 87, 87, 1207, 1862, 1883, 1893 of 4,391 | not computed |
| Isolation Forest | loud scans ranked 9, 21, 31, 40, 41 of 7,965; quiet scans 436 to 1,005 | 6 of 3,667 |

Isolation Forest top-20 host list: 1 attacker, 13 internal `192.168.10.x` workstations, 6 external addresses. That is 5% precision, roughly 180 times the random rate, with 19 hosts to review for each real one.

## Results: Wednesday (DoS) and transfer from Friday

| Method | P@5 | R@12 | Attacker host rank |
|---|---|---|---|
| Rank by flow count | 1.0 | 0.26 | 1 of 7,689 |
| Rank by distinct ports | 0.0 | 0.00 | 5 of 7,689 |
| Rank by distinct destination IPs | 0.0 | 0.00 | 191 of 7,689 |
| Logistic regression, trained on Friday | 1.0 | 0.19 | 1 of 7,689 |
| Isolation Forest, fit on Friday | 1.0 | 0.33 | 1 of 7,689 |
| Isolation Forest, fit on Wednesday | 1.0 | 0.33 | 1 of 7,689 |

R@12 is the share of all 27 attack windows found in the top 12, so the maximum possible is 12/27 = 0.44.

## Findings

- **No single rule carried over between days.** Distinct destination ports was the best single feature on Friday (a scan touches many ports). On Wednesday it failed completely (a flood hits one service, port 80). Flow count was the best rule on Wednesday.
- **Isolation Forest transferred best.** The forest fit on Friday scored about the same on Wednesday as the forest fit on Wednesday, with no labels used. It also recovered the most attack windows in the top 12 (0.33).
- **The Friday-trained logistic regression found the loudest windows but recovered fewer attack windows overall** than the flow-count rule (R@12 of 0.19 vs. 0.26). Its Friday coefficients are unstable, because there were only 6 positive windows per training set.
- **Ranking the attacker host is easy on both days.** The one-line flow-count rule puts it first on Wednesday, and flow count or port count does so on Friday. The methods differ only in how many attack windows they recover.
- **Unusual does not mean malicious.** On Friday, Isolation Forest ranks busy workstations (50 to 350 distinct destination IPs per window) above the attacker. The explanation view separates the patterns: many ports on one target (scan-like), many targets on few ports (fan-out), and long or heavy transfers.
- **The victim looks like the attacker.** On Friday, `192.168.10.50` ranks 4th. In its 02:50 window, 488 of its 560 outbound flows go to `172.16.0.1`, and 93,096 of its 93,169 inbound flows are PortScan flows from `172.16.0.1`. Its destination ports are mostly high numbers, which suggests reply traffic. The same host is the target of the Wednesday flood.
- **Heartbleed is not visible to these features.** Its 11 flows spread over several windows, and by flow count those windows rank between 3,914 and 8,688.

## Limitations

- Two days, one attacker address. Every attack in both files comes from `172.16.0.1`, probably a gateway or NAT address in the lab, so host-level results are effectively one data point. The windows from one attack are also not independent, so the 12 and 27 positives overstate the evidence.
- The benchmark is far richer in attacks than a real network at flow level. Window-level labeling brings it closer, but precision here still overstates production precision.
- Window labels are approximate. A window is positive if it contains any attack flow. On Wednesday, 3 of 27 positives have an attack-flow fraction below 0.5, and two slowloris windows are only about 5% and 1.5% attack flows. Windows that are all attack show 1 distinct port, while mixed windows show dozens. A likely reason is that the extra ports come from benign flows sharing the attacker's address, but this was not verified flow by flow.
- Several variants were compared while looking at test results, and the positive counts are small. Treat the ranks as exploratory, not as final performance.
- Timestamps carry no AM/PM marker, and the Wednesday file parses as May 7 instead of July 5. Windows are unaffected, but clock order is unreliable, so no time-based split was used on that file.
- A window with one or two attack flows cannot be told apart from quiet normal traffic using these features.

## Recommendations

- Score each host against its own history or peer group (workstations vs. servers) instead of against all hosts, which is the most likely way to cut workstation false alarms. Untested here, because each file covers only a few hours.
- Add direction-aware features, such as inbound vs. outbound flow ratios, so that targets are not flagged as sources. When a flagged host's top peer is also flagged, report the pair.
- Evaluate leaving one whole day out, across more days and attack types, before trusting any model.
- Add signals beyond volume (unusual destination ports, protocol-level rules) for low-volume exploits like Heartbleed. Untested here.

## Reproduce

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
jupyter notebook   # run notebooks 02 and 03
```
