import pandas as pd
from .models import ISO_COLS, log_scale


def zscores(feat, cols=ISO_COLS):
    X = log_scale(feat, cols)
    return (X - X.mean()) / X.std()


def morning_list(feat, score_col="iso_score", n=20, cols=ISO_COLS):
    """Top-n hosts by worst window, with the two biggest reasons each."""
    Z = zscores(feat, cols)
    best = (feat.loc[feat.groupby("Source IP")[score_col].idxmax()]
            .sort_values(score_col, ascending=False).head(n))

    def why(i):
        top2 = Z.loc[i].abs().sort_values(ascending=False).head(2).index
        return ", ".join(f"{c} ({Z.loc[i, c]:+.1f} sd)" for c in top2)

    return pd.DataFrame({
        "rank": range(1, len(best) + 1),
        "host": best["Source IP"].values,
        "window": best["window"].dt.strftime("%H:%M").values,
        "score": best[score_col].round(3).values,
        "why": [why(i) for i in best.index],
        "is_attack": best["label"].values,
    })
