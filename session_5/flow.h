#ifndef FLOW_H
#define FLOW_H

#include "parse.h"

/* Salidas opcionales: si no se abren, ese fichero simplemente no se escribe. */
int  flows_open(const char *path);      /* flows.csv    (--flows)    */
int  features_open(const char *path);   /* features.csv (--features) */

/* Procesa un paquete TCP/UDP valido: crea/actualiza/cierra flujos. */
void flow_process(const struct packet *p);

/* Fin de fichero: cierra (escribe) todos los flujos aun abiertos. */
void flows_finish(void);

unsigned long long flows_count(void);

#endif
