import pandas as pd


def load_flows(path, window="5min"):
    """Load a CIC-IDS2017 TrafficLabelling CSV and add window + is_attack."""
    df = pd.read_csv(path, encoding="latin1")
    df.columns = df.columns.str.strip()
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    n_bad = df["Timestamp"].isna().sum()
    if n_bad:
        print(f"Warning: dropping {n_bad} rows with unparsed timestamps")
        df = df.dropna(subset=["Timestamp"])
    df["window"] = df["Timestamp"].dt.floor(window)
    df["is_attack"] = (df["Label"].str.strip() != "BENIGN").astype(int)
    return df
