import pandas as pd 

def score(row):
    return row['bad_count']/row['count']

country = pd.read_csv("countrytable.csv")
asn = pd.read_csv("asntable.csv")


country['CCR'] = country.apply(score, axis=1)
asn['CCA'] = asn.apply(score, axis=1)

asn.to_csv("asntable.csv", index=False)
country.to_csv("countrytable.csv", index=False)