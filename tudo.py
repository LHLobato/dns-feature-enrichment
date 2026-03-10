import ast
import os
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from common_functions import get_numeric_features, get_date_features
import pandas as pd
from scipy.sparse import hstack, issparse, csr_matrix
import argparse
import torch
from torch.utils.data import DataLoader, TensorDataset

from MultiLayerPerceptron import MultiLayerPerceptron, train, test

# ── Argumentos ───────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument('--tfidf',        action='store_true', help='Usar TF-IDF')
parser.add_argument('--whois',        action='store_true', help='Usar whois-features')
parser.add_argument('--country',      action='store_true', help='Usar country-features')
parser.add_argument('--scores',       action='store_true', help='Usar scores de reputação')
parser.add_argument('--datefeatures', action='store_true', help='Usar features de data')
parser.add_argument('--typo',         action='store_true', help='Usar encoding ASCII de nomes (typosquatting)')
parser.add_argument('--exp',          type=str,   default='exp',           help='Nome do experimento')
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
MODEL_NAME = 'mlp'


# ── Pré-processamento ASCII para typosquatting ────────────────────────────────
def preprocess_name(names: list, max_len: int = 64) -> np.ndarray:
    """
    Converte cada nome de domínio em um vetor de inteiros ASCII com
    comprimento fixo `max_len`.
    - Nomes mais longos que max_len são truncados.
    - Nomes mais curtos recebem zero-padding à direita.

    Retorna np.ndarray de shape (N, max_len), dtype float32.

    CORREÇÃO do bug original: .append() retorna None em Python,
    então a lista era preenchida com None. Agora cada vetor é
    construído diretamente e acumulado com list.append(padded).
    """
    result = []
    for name in names:
        ascii_codes = [ord(c) for c in name[:max_len]]              # trunca se necessário
        padded      = ascii_codes + [0] * (max_len - len(ascii_codes))  # zero-padding
        result.append(padded)                                        # append do vetor, não de None
    return np.array(result, dtype=np.float32)                       # (N, max_len)


# ── Carregamento e merge de dados ─────────────────────────────────────────────
df = pd.read_csv("subset_50k.csv", index_col=False)

if args.whois:
    df_whois = pd.read_csv("whois-final.csv", index_col=False)
    df_whois = get_date_features(df_whois)
    if args.datefeatures:
        df = df.merge(df_whois[['name', 'lifetime', 'active_time', 'has_whois']], on='name', how='left')
    else:
        df = df.merge(df_whois[['name', 'has_whois']], on='name', how='left')

if args.country:
    df_country = pd.read_csv("50kcountry_enriched.csv", index_col=False)
    for col in ["ips", "countries", "asns"]:
        df_country[col] = df_country[col].apply(
            lambda x: ast.literal_eval(x) if pd.notna(x) and x.startswith('[') else []
        )
    if args.scores:
        df = df.merge(df_country[['name', 'countries', 'asns', 'has_country']], on='name', how='left')
    else:
        df = df.merge(df_country[['name', 'has_country']], on='name', how='left')

# ── Divisão treino / val / teste ──────────────────────────────────────────────
labels = df['malicious'].values

df_train, df_rest, y_train, y_rest = train_test_split(
    df, labels, test_size=0.30, stratify=labels, random_state=args.random_state
)
df_val, df_test, y_val, y_test = train_test_split(
    df_rest, y_rest, test_size=0.50, stratify=y_rest, random_state=args.random_state
)

# ── Scores de reputação (calculados só sobre o treino) ────────────────────────
if args.scores:
    print("Calculando rankings de reputação baseados apenas no treino...")

    ccr_map     = df_train.explode('countries').groupby('countries')['malicious'].mean().to_dict()
    cca_map     = df_train.explode('asns').groupby('asns')['malicious'].mean().to_dict()
    global_mean = df_train['malicious'].mean()

    def map_score(item_list, mapping_dict, default_val):
        if not isinstance(item_list, list) or len(item_list) == 0:
            return default_val
        scores = [mapping_dict.get(i, default_val) for i in item_list]
        return np.mean(scores) if scores else default_val

    for split in [df_train, df_val, df_test]:
        split['CCR'] = split['countries'].apply(lambda x: map_score(x, ccr_map, global_mean))
        split['CCA'] = split['asns'].apply(lambda x: map_score(x, cca_map, global_mean))

    df_train = df_train.drop(columns=['countries', 'asns'])
    df_val   = df_val.drop(columns=['countries', 'asns'])
    df_test  = df_test.drop(columns=['countries', 'asns'])

# ── Features de data ──────────────────────────────────────────────────────────
if args.datefeatures:
    lifetime_mean = df_train['lifetime'].mean()
    active_mean   = df_train['active_time'].mean()
    for split in [df_train, df_val, df_test]:
        split['lifetime']    = split['lifetime'].fillna(lifetime_mean)
        split['active_time'] = split['active_time'].fillna(active_mean)

# ── Extração de features ──────────────────────────────────────────────────────
os.makedirs("./joblib/", exist_ok=True)

if args.tfidf:
    print("Processando TF-IDF...")
    vectorizer    = TfidfVectorizer(analyzer='char', ngram_range=(3, 3), max_features=1024)
    X_train_tfidf = vectorizer.fit_transform(df_train['name'].astype(str))
    X_val_tfidf   = vectorizer.transform(df_val['name'].astype(str))
    X_test_tfidf  = vectorizer.transform(df_test['name'].astype(str))
    joblib.dump(vectorizer, f"./joblib/tfidf-{args.exp}.joblib")

print("Extraindo features léxicas e de DNS...")
X_train_num = get_numeric_features(df_train)
X_val_num   = get_numeric_features(df_val)
X_test_num  = get_numeric_features(df_test)

if args.typo:
    print(f"Gerando encoding ASCII dos nomes (max_len={args.max_len})...")
    X_train_typo = preprocess_name(df_train['name'].astype(str).tolist(), args.max_len)
    X_val_typo   = preprocess_name(df_val['name'].astype(str).tolist(),   args.max_len)
    X_test_typo  = preprocess_name(df_test['name'].astype(str).tolist(),  args.max_len)

# ── Concatenação final ────────────────────────────────────────────────────────
# Com --typo: a MLP recebe APENAS os vetores ASCII (ord), sem outras features.
# Sem --typo: concatena TF-IDF (opcional) + features numéricas/léxicas.
if args.typo:
    X_train_final = X_train_typo
    X_val_final   = X_val_typo
    X_test_final  = X_test_typo
else:
    parts_train, parts_val, parts_test = [], [], []

    if args.tfidf:
        parts_train.append(X_train_tfidf)
        parts_val.append(X_val_tfidf)
        parts_test.append(X_test_tfidf)

    parts_train.append(csr_matrix(X_train_num) if not issparse(X_train_num) else X_train_num)
    parts_val.append(csr_matrix(X_val_num)     if not issparse(X_val_num)   else X_val_num)
    parts_test.append(csr_matrix(X_test_num)   if not issparse(X_test_num)  else X_test_num)

    X_train_final = hstack(parts_train)
    X_val_final   = hstack(parts_val)
    X_test_final  = hstack(parts_test)

# ── Escalonamento ─────────────────────────────────────────────────────────────
if args.typo:
    # ord() já está em [0, 127] — normaliza direto, sem MinMaxScaler nem sparse
    print("Normalizando encoding ASCII (/ 127)...")
    X_train_final = X_train_final / 127.0
    X_val_final   = X_val_final   / 127.0
    X_test_final  = X_test_final  / 127.0
else:
    print("Escalonando dados para a MLP...")
    scaler        = MinMaxScaler()
    X_train_final = scaler.fit_transform(X_train_final)
    X_val_final   = scaler.transform(X_val_final)
    X_test_final  = scaler.transform(X_test_final)
    joblib.dump(scaler, f"./joblib/scaler-{args.exp}.joblib")

    # Garante arrays densos para o PyTorch
    if issparse(X_train_final):
        X_train_final = X_train_final.toarray()
        X_val_final   = X_val_final.toarray()
        X_test_final  = X_test_final.toarray()

# ── DataLoaders ───────────────────────────────────────────────────────────────
def make_loader(X, y, batch_size, shuffle):
    X_t = torch.tensor(X, dtype=torch.float32)
    y_t = torch.tensor(y, dtype=torch.long)
    return DataLoader(TensorDataset(X_t, y_t), batch_size=batch_size, shuffle=shuffle)

train_loader = make_loader(X_train_final, y_train, args.batch_size, shuffle=True)
val_loader   = make_loader(X_val_final,   y_val,   args.batch_size, shuffle=False)
test_loader  = make_loader(X_test_final,  y_test,  args.batch_size, shuffle=False)

# ── Instanciação da MLP ───────────────────────────────────────────────────────
input_dim = X_train_final.shape[1]
model = MultiLayerPerceptron(
    input_features  = input_dim,
    hidden_features = args.hidden_dim,
    output_classes  = 2,
    dropout_rate    = args.dropout,
).to(DEVICE)

print(f"\nMLP criada:")
print(f"  input_dim  = {input_dim}  "
      f"({'num' if not args.tfidf and not args.typo else ''}"
      f"{'+ tfidf' if args.tfidf else ''}"
      f"{'+ typo ' + str(args.max_len) if args.typo else ''} features)")
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
    f.write(f"Flags       : tfidf={args.tfidf} | whois={args.whois} | country={args.country} "
            f"| scores={args.scores} | datefeatures={args.datefeatures} | typo={args.typo}\n")
    f.write(f"Arquitetura : input={input_dim} | hidden={args.hidden_dim} "
            f"| layers={args.num_layers} | dropout={args.dropout}\n\n")
    f.write(f"Melhor época (val): {best_epoch}  |  Val Acc: {best_acc:.4f}\n\n")
    f.write(f"Test Loss : {test_loss:.4f}\n")
    f.write(f"Test Acc  : {test_acc:.4f}\n")
    f.write(f"Test Prec : {test_prec:.4f}\n")
    f.write(f"Test Rec  : {test_rec:.4f}\n")
    f.write(f"Test F1   : {test_f1:.4f}\n")
    f.write(f"Test AUC  : {test_auc:.4f}\n")

print(f"Log salvo em ./logs/{args.exp}-relatory.txt")
