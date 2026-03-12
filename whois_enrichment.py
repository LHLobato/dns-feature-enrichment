import whois 
import csv
import pandas as pd 
from concurrent.futures import ThreadPoolExecutor
import time
import random 
from common_functions import get_whois_features
from tqdm import tqdm 
import os 

df = pd.read_csv("dataset.csv")
df = df.head(232839)
dominios = df['name'].values
resultados = []

csv_file = 'whois-query-result.csv'

batch_size = 5000
batch_idx = 0 

for i in tqdm(range(0, len(dominios), batch_size), desc="Consultando WHOIS em Batches"):
    domain_batch = dominios[i:i+batch_size]
    with ThreadPoolExecutor(max_workers=5) as executor:
        resultados = list(executor.map(get_whois_features, domain_batch))
    resultados = pd.DataFrame(resultados)
    resultados["name"] = domain_batch
        
    file_exists = os.path.isfile(csv_file)
    resultados.to_csv(csv_file, mode='a', index=False, header=not file_exists)
    



