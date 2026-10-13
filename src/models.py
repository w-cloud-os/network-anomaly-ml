import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

ISO_COLS = ["flows", "n_dst_ports", "n_dst_ips",
            "no_reply_frac", "mean_bwd_pkts", "dur_s"]
LOGREG_COLS = ["n_dst_ips", "n_dst_ports", "no_reply_frac", "mean_bwd_pkts"]


def log_scale(feat, cols):
    return np.log1p(feat[cols].clip(lower=0))


def isolation_scores(feat, cols=ISO_COLS, seed=0, fit_on=None):
    """Higher = more anomalous. Fits on `fit_on` (default: feat itself)."""
    ref = feat if fit_on is None else fit_on
    iso = IsolationForest(n_estimators=300, random_state=seed)
    iso.fit(log_scale(ref, cols))
    return -iso.score_samples(log_scale(feat, cols))


def fit_logistic(train, test, cols=LOGREG_COLS, C=0.1):
    """Train on `train`, return (scores for `test`, coefficients)."""
    scaler = StandardScaler().fit(log_scale(train, cols))
    model = LogisticRegression(class_weight="balanced", C=C, max_iter=1000)
    model.fit(scaler.transform(log_scale(train, cols)), train["label"])
    scores = model.predict_proba(scaler.transform(log_scale(test, cols)))[:, 1]
    return scores, dict(zip(cols, model.coef_[0].round(2)))
