
from concurrent.futures import ThreadPoolExecutor
import pandas as pd 
from common_functions import get_country


df = pd.read_csv("subset_50k.csv")

dominios = df['name'].values

with ThreadPoolExecutor(max_workers=20) as executor:
    resultados = list(executor.map(get_country, dominios))

resultados = pd.DataFrame(resultados)
resultados["countries"] = resultados['countries'].apply(str)
df = df.merge(resultados, on="name", how="left")
df.to_csv("50kcountry_enriched.csv", index=False)