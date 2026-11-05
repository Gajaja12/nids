#ifndef WINDOW_H
#define WINDOW_H

#include "parse.h"

int  windows_open(const char *path);          /* abre windows.csv; 0 = ok */
void window_process(const struct packet *p);  /* un paquete TCP/UDP valido */
void windows_finish(void);                    /* escribe la ultima ventana */

#endif
