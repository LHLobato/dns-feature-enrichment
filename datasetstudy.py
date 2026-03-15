import pandas as pd 
import matplotlib.pyplot as plt 

df = pd.read_csv('dataset.csv', index_col=False)
df.drop(columns=["malicious"], inplace=True)
corr = df.corr(numeric_only=True)

corr.style.background_gradient(cmap="coolwarm").format(precision=2)

import seaborn as sns

# Configura o tamanho da figura
plt.figure(figsize=(12, 10))

# Plota o heatmap
# annot=True coloca os números dentro dos quadrados
# fmt=".4f" define as 4 casas decimais que você queria
sns.heatmap(corr, annot=True, fmt=".4f", cmap="coolwarm", vmin=-1, vmax=1)

plt.title("Matriz de Correlação")


# Se estiver no seu PC com interface gráfica:
plt.show()