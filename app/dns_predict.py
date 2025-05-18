import torch
import torch.nn as nn
import pandas as pd

# Define the same model architecture used during training
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


def predict_with_dns_model(df: pd.DataFrame, model_path: str = "dns_tunnel_classifier.pt") -> pd.DataFrame:
    """
    Predict using a PyTorch model saved as state_dict.

    Parameters:
        df (pd.DataFrame): Input DataFrame with features (cleaned).
        model_path (str): Path to the .pt file containing state_dict.

    Returns:
        pd.DataFrame: DataFrame with prediction_score and predicted_label columns added.
    """
    # Drop label column if it exists
    df = df.drop(columns=["label"], errors="ignore")

    # Clean any NaN or infinite values
    df = df.fillna(0).replace([float("inf"), float("-inf")], 0)

    # Convert DataFrame to torch tensor
    X = torch.tensor(df.values, dtype=torch.float32)

    # Initialize model and load weights
    input_dim = X.shape[1]
    model = DNSTunnelClassifier(input_dim)
    model.load_state_dict(torch.load(model_path, map_location="cpu"))
    model.eval()

    # Predict
    with torch.no_grad():
        scores = model(X).squeeze().numpy()
        labels = (scores > 0.5).astype(int)

    # Add prediction results to DataFrame
    df["prediction_score"] = scores
    df["predicted_label"] = labels

    return df
