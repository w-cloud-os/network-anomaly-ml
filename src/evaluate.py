def precision_at_k(data, score_col, k):
    return data.sort_values(score_col, ascending=False).head(k)["label"].mean()


def recall_at_k(data, score_col, k):
    top = data.sort_values(score_col, ascending=False).head(k)
    return top["label"].sum() / data["label"].sum()


def positive_ranks(data, score_col):
    """Ranks (1 = most suspicious) of every true attack window."""
    ranks = data[score_col].rank(ascending=False, method="first")
    return sorted(ranks[data["label"] == 1].astype(int).tolist())


def host_rank(data, score_col, host):
    """Rank of a host using its worst window, and the total number of hosts."""
    h = data.groupby("Source IP")[score_col].max().sort_values(ascending=False)
    return list(h.index).index(host) + 1, len(h)
