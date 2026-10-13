def build_host_windows(df):
    """One row per (source IP, time window) with behavior features."""
    df = df.copy()
    df["no_reply"] = (df["Total Backward Packets"] == 0).astype(int)
    df["rst"] = (df["RST Flag Count"] > 0).astype(int)

    feat = df.groupby(["Source IP", "window"]).agg(
        flows=("is_attack", "size"),
        n_dst_ports=("Destination Port", "nunique"),
        n_dst_ips=("Destination IP", "nunique"),
        mean_fwd_pkts=("Total Fwd Packets", "mean"),
        mean_bwd_pkts=("Total Backward Packets", "mean"),
        mean_duration=("Flow Duration", "mean"),
        no_reply_frac=("no_reply", "mean"),
        rst_frac=("rst", "mean"),
        attack_flows=("is_attack", "sum"),
    ).reset_index()

    feat["label"] = (feat["attack_flows"] > 0).astype(int)   # for checking only
    feat["attack_frac"] = feat["attack_flows"] / feat["flows"]
    feat["flows_per_dst_ip"] = feat["flows"] / feat["n_dst_ips"]
    feat["flows_per_dst_port"] = feat["flows"] / feat["n_dst_ports"]
    feat["dur_s"] = feat["mean_duration"].clip(lower=0) / 1e6
    return feat
