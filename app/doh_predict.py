from typing import Optional

import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
from deepctr.feature_column import DenseFeat, get_feature_names


def predict_with_doh_deepfm_model(df: pd.DataFrame, model_path: str = "doh_deepfm_model") -> Optional[pd.DataFrame]:
    """
    Perform prediction using the DeepFM SavedModel on a given input DataFrame.

    Parameters:
        df (pd.DataFrame): Input dataframe with raw features.
        model_path (str): Path to the SavedModel folder (default: "doh_deepfm_model").

    Returns:
        pd.DataFrame: DataFrame with added 'prediction_score' and 'predicted_label' columns.
    """
    if df.empty:
        print("ℹ️ No DoH traffic found in PCAP file. Skipping DoH prediction.")
        return None

    # --- 1. Define dense feature list by removing non-numeric or ID-related columns ---
    drop_cols = ['SourceIP', 'DestinationIP', 'TimeStamp', 'DestinationPort', 'SourcePort', 'Label']
    dense_features = [col for col in df.columns if col not in drop_cols]

    # --- 2. Drop irrelevant columns and clean data ---
    df = df.drop(columns=drop_cols, errors='ignore')
    df = df.fillna(0).replace([np.inf, -np.inf], 0)

    # --- 3. Scale the dense features ---
    scaler = StandardScaler()
    df[dense_features] = scaler.fit_transform(df[dense_features])

    # --- 4. Prepare input format for DeepFM model ---
    feature_columns = [DenseFeat(feat, 1) for feat in dense_features]
    feature_names = get_feature_names(feature_columns)
    model_input = {name: df[name].values for name in feature_names}

    # --- 5. Load the DeepFM SavedModel ---
    model = tf.keras.models.load_model(model_path, compile=False)

    # --- 6. Predict scores and labels ---
    preds = model.predict(model_input, batch_size=512)
    df["prediction_score"] = preds
    df["predicted_label"] = (preds > 0.5).astype(int)

    return df
