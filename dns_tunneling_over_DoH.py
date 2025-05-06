# xDeepFM for DoH tunneling (F1-F28 features) using CIRA-CIC-DoHBrw-2020 dataset
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, classification_report
from deepctr.feature_column import SparseFeat, DenseFeat, get_feature_names
from deepctr.models import xDeepFM
import tensorflow as tf

# -------- 1. Load CSVs --------
# Load both CSV files
benign = pd.read_csv('Doh_dataset/benign.csv')
mal = pd.read_csv('Doh_dataset/malicious.csv')

# Concatenate them
data = pd.concat([benign, mal], ignore_index=True)

# Standardize and map textual labels to numeric binary labels
data['Label'] = data['Label'].str.strip().map({'Benign': 0, 'Malicious': 1})

# Shuffle the combined dataset
data = data.sample(frac=1.0, random_state=42)

# -------- 2. Feature list --------
sparse_features = ['SourceIP', 'DestinationIP']
dense_features = [col for col in data.columns if col not in ['SourceIP', 'DestinationIP', 'TimeStamp', 'Label']]


# -------- 3. Scale dense features and Convert sparse features to string --------
for feat in sparse_features:
    data[feat] = data[feat].astype(str)

scaler = StandardScaler()
data[dense_features] = scaler.fit_transform(data[dense_features])
for feat in sparse_features:
    lbe = LabelEncoder()
    data[feat] = lbe.fit_transform(data[feat])

data[dense_features] = scaler.fit_transform(
    np.nan_to_num(data[dense_features], nan=0.0, posinf=0.0, neginf=0.0)
)


# -------- 4. Build feature columns --------
feature_columns = (
    [SparseFeat(feat, vocabulary_size=data[feat].nunique(), embedding_dim=8) for feat in sparse_features] +
    [DenseFeat(feat, 1) for feat in dense_features]
)
feature_names = get_feature_names(feature_columns)

# -------- 5. Train / test split --------
train, test = train_test_split(data, test_size=0.2,
                               stratify=data['Label'], random_state=42)
train_input = {name: train[name].values for name in feature_names}
test_input  = {name:  test[name].values for name in feature_names}

# -------- 6. Build & compile model --------
model = xDeepFM(feature_columns, feature_columns,
                dnn_hidden_units=(128, 64),
                cin_layer_size=(128, 128, 64),
                task='binary')
model.compile(optimizer='adam',
              loss='binary_crossentropy',
              metrics=[tf.keras.metrics.BinaryAccuracy(), tf.keras.metrics.AUC()])

# -------- 7. Train --------
early_stop = tf.keras.callbacks.EarlyStopping(monitor='val_loss',
                                              patience=5,
                                              restore_best_weights=True)
model.fit(train_input, train['Label'].values,
          epochs=70,
          batch_size=512,
          validation_split=0.1,
          callbacks=[early_stop],
          verbose=2)

# -------- 8. Evaluate --------
pred = model.predict(test_input, batch_size=1024)
print("ROC‑AUC:", roc_auc_score(test['Label'], pred))
print(classification_report(test['Label'], (pred > 0.5).astype(int)))

# -------- 9. Save model --------
model.save('doh_xdeepfm_f28.h5')
