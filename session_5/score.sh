#!/bin/sh
# Uso: sh score.sh alerts.csv labels.csv [alerts.txt]
# Alerta (o incidente) = verdadero positivo si existe una etiqueta con la MISMA regla y el MISMO origen.
# Precision = TP / total.  Recall = etiquetas con alguna alerta / etiquetas.
# Con alerts.txt como tercer argumento, calcula tambien la precision POR INCIDENTE.
[ $# -ge 2 ] || { echo "uso: sh score.sh alerts.csv labels.csv [alerts.txt]"; exit 2; }
awk -F, '
    NR == FNR {                       # 1er fichero: etiquetas (rule,src,start,end)
        if ($1 == "rule") next
        lab[$1 "," $2] = 1; nl++; next
    }
    FNR == 1 { next }                 # cabecera de alerts.csv (time,rule,src,dst,detail)
    {
        na++; k = $2 "," $3
        if (k in lab) { tp++; hit[k] = 1 }
        else { fp++; print "ALERTA SIN ETIQUETA: " $0 }
    }
    END {
        for (k in lab) if (!(k in hit)) print "SIN ALERTA (falso negativo): " k
        nh = 0; for (k in hit) nh++
        printf "alertas    : %d  TP=%d  FP=%d  precision = %.3f\n", na, tp, fp, (na ? tp / na : 0)
        printf "recall     : %.3f  (%d de %d etiquetas)\n", (nl ? nh / nl : 0), nh, nl
    }' "$2" "$1"

if [ -n "$3" ]; then
    # alerts.txt: "YYYY-MM-DD HH:MM:SS HH:MM:SS regla src > dst alerts=N detalle" (separado por espacios)
    awk '
        NR == FNR { if ($0 ~ /^rule,/) next; split($0, a, ","); lab[a[1] "," a[2]] = 1; next }
        { ni++; k = $4 "," $5; if (k in lab) tpi++; else print "INCIDENTE SIN ETIQUETA: " $0 }
        END { printf "incidentes : %d  TP=%d  FP=%d  precision = %.3f\n", ni, tpi, ni - tpi, (ni ? tpi / ni : 0) }
    ' "$2" "$3"
fi
