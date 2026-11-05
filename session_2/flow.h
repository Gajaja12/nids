#ifndef FLOW_H
#define FLOW_H

#include "parse.h"

/* Abre flows.csv (escribe la cabecera) y activa el modo flujos. 0 = ok. */
int  flows_open(const char *path);
int  flows_enabled(void);

/* Procesa un paquete TCP/UDP valido: crea/actualiza/cierra flujos. */
void flow_process(const struct packet *p);

/* Fin de fichero: cierra (escribe) todos los flujos aun abiertos. */
void flows_finish(void);

#endif
