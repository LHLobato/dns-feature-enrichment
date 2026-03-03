
import ast
import os

import joblib
from matplotlib import pyplot as plt
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from xgboost import XGBClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from common_functions import get_numeric_features, get_date_features
import pandas as pd
from scipy.sparse import hstack
import sys 
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--tfidf', action='store_true', help='Usar TF-IDF')
parser.add_argument('--whois', action='store_true', help='Usar whois-features')
parser.add_argument('--country', action='store_true', help='Usar country-features')
parser.add_argument('--exp', type=str, default='exp', help='Nome do experimento')
parser.add_argument("--random_state", type=int, default=42, help="Seed da divisão de treino")
parser.add_argument('--model', type=str, default='xgb', 
                    choices=['xgb', 'rf', 'lr', 'svm'], 
                    help='Modelo: xgb (XGBoost), rf (Random Forest), lr (Logistic Regression), svm (Linear SVM)')
args = parser.parse_args()



df = pd.read_csv("subset_50k.csv", index_col=False)


if args.whois: 
    df_whois = pd.read_csv("whois-final.csv", index_col=False)
    df_whois = get_date_features(df_whois)
    df = df.merge(df_whois[['name', 'lifetime', 'active_time', 'has_whois']], on='name', how='left')


if args.country: 
    df_country = pd.read_csv("50kcountry_enriched.csv", index_col=False)
    for col in ["ips", "countries", "asns"]:
        df_country[col] = df_country[col].apply(lambda x: ast.literal_eval(x) if pd.notna(x) and x.startswith('[') else [])
    

    df = df.merge(df_country[['name', 'has_country', 'countries', 'asns']], on='name', how='left')

labels = df['malicious'].values
df_train, df_rest, y_train, y_rest = train_test_split(
    df, labels, test_size=0.30, stratify=labels, random_state=args.random_state
)

df_val, df_test, y_val, y_test = train_test_split(
    df_rest, y_rest, test_size=0.50, stratify=y_rest, random_state=args.random_state
)

if args.country:
    print("Calculando rankings de reputação baseados apenas no treino...")
    
    df_train_exp = df_train.explode('countries')
    
    ccr_map = df_train_exp.groupby('countries')['malicious'].mean().to_dict()
    global_mean_ccr = df_train['malicious'].mean() 

    df_train_asn_exp = df_train.explode('asns')
    cca_map = df_train_asn_exp.groupby('asns')['malicious'].mean().to_dict()
    global_mean_cca = global_mean_ccr

    def map_score(item_list, mapping_dict, default_val):
        if not isinstance(item_list, list) or len(item_list) == 0:
            return default_val
        
        scores = [mapping_dict.get(i, default_val) for i in item_list]
        return np.mean(scores) if scores else default_val

    for target_df in [df_train, df_test]:
        target_df['CCR'] = target_df['countries'].apply(lambda x: map_score(x, ccr_map, global_mean_ccr))
        target_df['CCA'] = target_df['asns'].apply(lambda x: map_score(x, cca_map, global_mean_cca))

    df_train = df_train.drop(columns=['countries', 'asns'])
    df_test = df_test.drop(columns=['countries', 'asns'])

if args.whois: 
    lifetime_mean = df_train['lifetime'].mean()
    active_mean = df_train['active_time'].mean()
    df_train['lifetime'] = df_train['lifetime'].fillna(lifetime_mean)
    df_train['active_time'] = df_train['active_time'].fillna(active_mean)
    df_test['lifetime'] = df_test['lifetime'].fillna(lifetime_mean)
    df_test['active_time'] = df_test['active_time'].fillna(active_mean)

os.makedirs("./joblib/",exist_ok=True)
if args.tfidf:
    print("Processando TF-IDF...")
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 3), max_features=1024)
    X_train_tfidf = vectorizer.fit_transform(df_train['name'].astype(str))
    X_test_tfidf = vectorizer.transform(df_test['name'].astype(str))
    joblib.dump(vectorizer, "./joblib/tfidfwhois.joblib")

    print("Extraindo features léxicas e de DNS...")

X_train_num = get_numeric_features(df_train)
X_test_num = get_numeric_features(df_test)

if args.tfidf:
    X_train_final = hstack([X_train_tfidf, X_train_num])
    X_test_final = hstack([X_test_tfidf, X_test_num])
else:
    X_train_final = X_train_num 
    X_test_final = X_test_num 


models = {
    'xgb': XGBClassifier(
        n_estimators=1000, learning_rate=0.01, max_depth=8, 
        subsample=0.6, colsample_bytree=0.6, gamma=0.2,
        tree_method='hist', eval_metric="auc", random_state=args.random_state, n_jobs=-1
    ),
    'rf': RandomForestClassifier(
        n_estimators=500, max_depth=15, min_samples_split=5,
        class_weight='balanced', random_state=args.random_state, n_jobs=-1
    ),
    # SGD com loss='log_loss' equivale a Regressão Logística
    'lr': SGDClassifier(
        loss='log_loss', penalty='l2', max_iter=2000, 
        class_weight='balanced', random_state=args.random_state, n_jobs=-1
    ),
    # SGD com loss='hinge' equivale a SVM Linear
    'svm': SGDClassifier(
        loss='hinge', penalty='l2', max_iter=2000, 
        class_weight='balanced', random_state=args.random_state, n_jobs=-1
    )
}

selected_model = models[args.model]

# --- Escalonamento (Obrigatório para LR e SVM) ---
if args.model in ['lr', 'svm']:
    print(f"Escalonando dados para {args.model.upper()}...")
    scaler = MinMaxScaler()
    # Para matrizes esparsas (TF-IDF), o fit_transform funciona direto no hstack
    X_train_final = scaler.fit_transform(X_train_final)
    X_test_final = scaler.transform(X_test_final)
    joblib.dump(scaler, f"./joblib/scaler-{args.exp}.joblib")

print(f"Treinando o modelo: {args.model.upper()}...")
selected_model.fit(X_train_final, y_train)


y_prob = selected_model.predict_proba(X_test_final)[:, 1]
y_pred = selected_model.predict(X_test_final)

auc_score = roc_auc_score(y_test, y_prob)
report = classification_report(y_test, y_pred)

print(f"\nROC AUC Final: {auc_score:.4f}")
print(report)

os.makedirs("./logs/",exist_ok=True)
with open(f"./logs/{args.exp}-relatory.txt", "w") as f:
    f.write(f"ROC AUC: {auc_score:.4f}\n")
    f.write(report)

joblib.dump(selected_model, f"./joblib/{args.exp}-{args.model}.joblib")