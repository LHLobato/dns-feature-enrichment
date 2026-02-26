
from concurrent.futures import ThreadPoolExecutor
import pandas as pd 
from common_functions import get_country


df = pd.read_csv("dataset.csv")
ben = df[df['malicious'] == 0]['name'].values
mal = df[df['malicious'] == 1]['name'].values
dominios = list(ben[:10000]) + list(mal[:10000])

with ThreadPoolExecutor(max_workers=20) as executor:
    resultados = list(executor.map(get_country, dominios))

resultados = pd.DataFrame(resultados)
resultados["countries"] = resultados['countries'].apply(str)

resultados.to_csv("countries.csv", index=False)