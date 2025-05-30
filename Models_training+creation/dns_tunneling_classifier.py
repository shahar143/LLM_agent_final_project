# dns_tunnel_classifier.py
# -----------------------------------------------
# Deep Feed-Forward network for DNS-Tunneling detection
# Architecture: 5 hidden layers (18-20-11-7-17)
# Activations: LeakyReLU (layer-1), ReLU (layers 2-5)
# Dropout: 0.25 after layer-2, 0.20 after layer-5
# Output: single neuron + Sigmoid  → binary class (1 = tunnel, 0 = normal)
# -----------------------------------------------
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# ---------- 1. Dataset wrapper ----------
class DNSDataset(Dataset):
    """Loads the engineered CSV and returns (features, label) tensors."""
    def __init__(self, csv_path: str):
        df = pd.read_csv(csv_path)

        # Clean and preprocess
        numeric_cols = df.columns.drop('label')
        df[numeric_cols] = df[numeric_cols].apply(pd.to_numeric, errors='coerce')
        df[numeric_cols] = df[numeric_cols].fillna(0).replace([np.inf, -np.inf], 0)
        df['label'] = df['label'].astype(float)

        df = df.drop(columns=['dst_ip_len', 'src_ip_len'], errors='ignore')
        df = df[df['response_size'] != 0.0]

        print(f"Number of rows after filtering: {df.shape[0]}")
        label_counts = df['label'].value_counts()
        print(f"Number of records with label 0: {label_counts.get(0.0, 0)}")
        print(f"Number of records with label 1: {label_counts.get(1.0, 0)}")

        self.X = torch.tensor(df.drop(columns=['label']).values, dtype=torch.float32)
        self.y = torch.tensor(df['label'].values, dtype=torch.float32).unsqueeze(1)

    def __len__(self):
        return len(self.y)

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]

# ---------- 2. Network definition ----------
class DNSTunnelClassifier(nn.Module):
    def __init__(self, input_dim: int):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, 18)
        self.act1 = nn.LeakyReLU()
        self.fc2 = nn.Linear(18, 20)
        self.act2 = nn.ReLU()
        self.do2  = nn.Dropout(p=0.25)
        self.fc3 = nn.Linear(20, 11)
        self.act3 = nn.ReLU()
        self.fc4 = nn.Linear(11, 7)
        self.act4 = nn.ReLU()
        self.fc5 = nn.Linear(7, 17)
        self.act5 = nn.ReLU()
        self.do5  = nn.Dropout(p=0.20)
        self.out  = nn.Linear(17, 1)
        self.sig  = nn.Sigmoid()

    def forward(self, x):
        x = self.act1(self.fc1(x))
        x = self.do2(self.act2(self.fc2(x)))
        x = self.act3(self.fc3(x))
        x = self.act4(self.fc4(x))
        x = self.do5(self.act5(self.fc5(x)))
        return self.sig(self.out(x))

# ---------- 3. Training / evaluation helpers ----------
def train_epoch(model, loader, loss_fn, optim):
    model.train()
    epoch_loss = 0.0
    for X, y in loader:
        optim.zero_grad()
        preds = model(X)
        loss = loss_fn(preds, y)
        loss.backward()
        optim.step()
        epoch_loss += loss.item() * len(y)
    return epoch_loss / len(loader.dataset)

@torch.no_grad()
def evaluate(model, loader):
    model.eval()
    all_preds, all_labels = [], []
    for X, y in loader:
        probs = model(X)
        all_preds.append((probs > 0.5).int().cpu().numpy())
        all_labels.append(y.int().cpu().numpy())
    y_true = np.vstack(all_labels)
    y_pred = np.vstack(all_preds)
    acc = accuracy_score(y_true, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average='binary', zero_division=0
    )
    return acc, prec, rec, f1

# ---------- 4. Main training script ----------
def main(csv_path: str, epochs: int = 5, batch_size: int = 128, lr: float = 1e-3):
    full_ds = DNSDataset(csv_path)
    input_dim = full_ds.X.shape[1]

    # Train/Val/Test split (70/10/20)
    all_indices = np.arange(len(full_ds))
    train_idx, temp_idx = train_test_split(
        all_indices, test_size=0.3, stratify=full_ds.y, random_state=42
    )
    val_idx, test_idx = train_test_split(
        temp_idx, test_size=0.3, stratify=full_ds.y[temp_idx], random_state=42
    )

    train_ds = torch.utils.data.Subset(full_ds, train_idx)
    val_ds   = torch.utils.data.Subset(full_ds, val_idx)
    test_ds  = torch.utils.data.Subset(full_ds, test_idx)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader   = DataLoader(val_ds, batch_size=batch_size, shuffle=False)
    test_loader  = DataLoader(test_ds, batch_size=batch_size, shuffle=False)

    model = DNSTunnelClassifier(input_dim)
    loss_fn = nn.BCELoss()
    optim = torch.optim.Adam(model.parameters(), lr=lr)

    for ep in range(1, epochs + 1):
        tr_loss = train_epoch(model, train_loader, loss_fn, optim)
        val_acc, val_prec, val_rec, val_f1 = evaluate(model, val_loader)
        print(
            f"Epoch {ep:02d} | loss={tr_loss:.4f} | "
            f"val_acc={val_acc:.3f} prec={val_prec:.3f} rec={val_rec:.3f} f1={val_f1:.3f}"
        )

    print("\n--- Final Evaluation on Test Set ---")
    test_acc, test_prec, test_rec, test_f1 = evaluate(model, test_loader)
    print(f"Test acc={test_acc:.3f} prec={test_prec:.3f} rec={test_rec:.3f} f1={test_f1:.3f}")

    torch.save(model.state_dict(), "dns_tunnel_classifier.pt")
    print("Model saved to dns_tunnel_classifier.pt")

if __name__ == "__main__":
    main("Dns_dataset/dns_dataset.csv")
