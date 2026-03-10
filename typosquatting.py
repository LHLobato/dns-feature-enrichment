import os
import numpy as np
from sklearn.model_selection import train_test_split
import pandas as pd
import argparse
import torch
from torch.utils.data import DataLoader, TensorDataset

from MultiLayerPerceptron import MultiLayerPerceptron, train, test

# ── Argumentos ───────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument('--exp',          type=str,   default='typo_exp',      help='Nome do experimento')
parser.add_argument('--random_state', type=int,   default=42,              help='Seed da divisão de treino')
parser.add_argument('--num_epochs',   type=int,   default=50,              help='Número de épocas')
parser.add_argument('--batch_size',   type=int,   default=256,             help='Tamanho do batch')
parser.add_argument('--hidden_dim',   type=int,   default=256,             help='Dimensão das camadas ocultas')
parser.add_argument('--num_layers',   type=int,   default=4,               help='Número de camadas ocultas')
parser.add_argument('--dropout',      type=float, default=0.2,             help='Taxa de dropout')
parser.add_argument('--max_len',      type=int,   default=64,              help='Comprimento máximo do nome (ASCII padding)')
parser.add_argument('--output_dir',   type=str,   default='./checkpoints', help='Diretório para salvar o modelo')
args = parser.parse_args()

DEVICE     = 'cuda' if torch.cuda.is_available() else 'cpu'
MODEL_NAME = 'mlp_typo'


# ── Pré-processamento ASCII ───────────────────────────────────────────────────
def preprocess_name(names: list, max_len: int = 64) -> np.ndarray:
    result = []
    for name in names:
        ascii_codes = [ord(c) for c in name[:max_len]]
        padded      = ascii_codes + [0] * (max_len - len(ascii_codes))
        result.append(padded)
    return np.array(result, dtype=np.float32)   # (N, max_len)


# ── Carregamento ──────────────────────────────────────────────────────────────
df     = pd.read_csv("subset_50k.csv", index_col=False)
labels = df['malicious'].values

# ── Divisão treino / val / teste ──────────────────────────────────────────────
df_train, df_rest, y_train, y_rest = train_test_split(
    df, labels, test_size=0.30, stratify=labels, random_state=args.random_state
)
df_val, df_test, y_val, y_test = train_test_split(
    df_rest, y_rest, test_size=0.50, stratify=y_rest, random_state=args.random_state
)

# ── Encoding ASCII ────────────────────────────────────────────────────────────
print(f"Gerando encoding ASCII (max_len={args.max_len})...")
X_train = preprocess_name(df_train['name'].astype(str).tolist(), args.max_len)
X_val   = preprocess_name(df_val['name'].astype(str).tolist(),   args.max_len)
X_test  = preprocess_name(df_test['name'].astype(str).tolist(),  args.max_len)

# ── DataLoaders ───────────────────────────────────────────────────────────────
def make_loader(X, y, batch_size, shuffle):
    X_t = torch.tensor(X, dtype=torch.float32)
    y_t = torch.tensor(y, dtype=torch.long)
    return DataLoader(TensorDataset(X_t, y_t), batch_size=batch_size, shuffle=shuffle)

train_loader = make_loader(X_train, y_train, args.batch_size, shuffle=True)
val_loader   = make_loader(X_val,   y_val,   args.batch_size, shuffle=False)
test_loader  = make_loader(X_test,  y_test,  args.batch_size, shuffle=False)

# ── Instanciação da MLP ───────────────────────────────────────────────────────
model = MultiLayerPerceptron(
    input_features  = args.max_len,
    hidden_features = args.hidden_dim,
    output_classes  = 2,
    dropout_rate    = args.dropout,
).to(DEVICE)

print(f"\nMLP (typo-only):")
print(f"  input_dim  = {args.max_len} (ord por caractere)")
print(f"  hidden_dim = {args.hidden_dim}")
print(f"  num_layers = {args.num_layers}")
print(f"  dropout    = {args.dropout}")
print(f"  device     = {DEVICE}\n")

# ── Treinamento ───────────────────────────────────────────────────────────────
best_acc, best_epoch = train(
    model        = model,
    num_epochs   = args.num_epochs,
    train_loader = train_loader,
    val_loader   = val_loader,
    output_dir   = args.output_dir,
    model_name   = MODEL_NAME,
    device       = DEVICE,
)

print(f"\nMelhor época: {best_epoch}  |  Melhor Val Acc: {best_acc:.4f}")

# ── Carrega melhor checkpoint ─────────────────────────────────────────────────
best_ckpt = os.path.join(args.output_dir, f"{MODEL_NAME}_{args.num_epochs}.pth")
model.load_state_dict(torch.load(best_ckpt, map_location=DEVICE))
print(f"Checkpoint carregado: {best_ckpt}\n")

# ── Teste ─────────────────────────────────────────────────────────────────────
test_loss, test_acc, test_prec, test_rec, test_f1, test_auc = test(
    model       = model,
    test_loader = test_loader,
    model_name  = MODEL_NAME,
    device      = DEVICE,
)

# ── Salva log ─────────────────────────────────────────────────────────────────
os.makedirs("./logs/", exist_ok=True)
with open(f"./logs/{args.exp}-relatory.txt", "w") as f:
    f.write(f"Experimento : {args.exp}\n")
    f.write(f"Features    : typo-only (ASCII ord, max_len={args.max_len})\n")
    f.write(f"Arquitetura : input={args.max_len} | hidden={args.hidden_dim} "
            f"| layers={args.num_layers} | dropout={args.dropout}\n\n")
    f.write(f"Melhor época (val): {best_epoch}  |  Val Acc: {best_acc:.4f}\n\n")
    f.write(f"Test Loss : {test_loss:.4f}\n")
    f.write(f"Test Acc  : {test_acc:.4f}\n")
    f.write(f"Test Prec : {test_prec:.4f}\n")
    f.write(f"Test Rec  : {test_rec:.4f}\n")
    f.write(f"Test F1   : {test_f1:.4f}\n")
    f.write(f"Test AUC  : {test_auc:.4f}\n")

print(f"Log salvo em ./logs/{args.exp}-relatory.txt")