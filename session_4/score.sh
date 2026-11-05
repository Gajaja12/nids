#!/bin/sh
# Uso: sh score.sh alerts.csv office-attacks.labels.csv
# Alerta = verdadero positivo si existe una etiqueta con la MISMA regla y el MISMO origen.
# Precision = TP / alertas.  Recall = etiquetas con alguna alerta / etiquetas.
[ $# -eq 2 ] || { echo "uso: sh score.sh alerts.csv labels.csv"; exit 2; }
awk -F, '
    NR == FNR {                       # 1er fichero: etiquetas (rule,src,start,end)
        if ($1 == "rule") next        # cabecera
        lab[$1 "," $2] = 1; nl++; next
    }
    FNR == 1 { next }                 # cabecera de alerts.csv (time,rule,src,dst,detail)
    {
        na++; k = $2 "," $3
        if (k in lab) { tp++; hit[k] = 1 }
        else { fp++; print "FALSO POSITIVO: " $0 }
    }
    END {
        for (k in lab) if (!(k in hit)) print "SIN ALERTA (falso negativo): " k
        nh = 0; for (k in hit) nh++
        printf "alertas=%d  TP=%d  FP=%d\n", na, tp, fp
        printf "precision = %.3f\n", (na ? tp / na : 0)
        printf "recall    = %.3f  (%d de %d etiquetas)\n", (nl ? nh / nl : 0), nh, nl
    }' "$2" "$1"
