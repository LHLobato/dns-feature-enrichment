#!/bin/bash


PYTHON_SCRIPT="machine_learning.py"

ENSEMBLEPATH="ensemble.txt"
#MODELS=("xgb" "rf" "knn" "lr")

MODELS=("ensemble")

FEATURE_FLAGS="--whois --country --datefeatures --scores"


echo "==========================================================================="
echo "Iniciando Bateria de Experimentos: WHOIS + COUNTRY + SCORES + DATAFEATURES"
echo "==========================================================================="

STATES=(0 100 1000)
for STATE in "${STATES[@]}"
do
    for MODEL in "${MODELS[@]}"
    do

        EXP_NAME="exp_${MODEL}_full_features_state_${STATE}"
        
        echo "----------------------------------------------------------"
        echo "Rodando: $MODEL com o experimento: $EXP_NAME"
        echo "----------------------------------------------------------"
        
        python3 "$PYTHON_SCRIPT" \
            --model "$MODEL" \
            --exp "$EXP_NAME" \
            $FEATURE_FLAGS \
            --ensemblepath "$ENSEMBLEPATH"\
            --ensemblemode "Stacking"\
            --random_state $STATE


        if [ $? -eq 0 ]; then
            echo "Sucesso: $EXP_NAME concluído."
        else
            echo "Erro: Falha ao processar $MODEL. Verifique os logs."
        fi
    done
done 
echo "=========================================================="
echo "Todos os experimentos foram concluídos!"
echo "Verifique o arquivo ./logs/experiments_results.csv"
echo "=========================================================="
