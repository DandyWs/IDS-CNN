import pandas as pd

def preprocess_csv(df):
    # Convert all non-numeric columns to numeric using factorize (label encoding)
    for col in df.columns:
        if df[col].dtype == 'object':
            df[col], _ = pd.factorize(df[col])
    df = df.fillna(0)
    return df