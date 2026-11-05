#ifndef LABELS_H
#define LABELS_H

#include <stdint.h>

/* Lee un fichero rule,src,start,end. 0 = ok. Debe llamarse ANTES de abrir las
   tablas (la cabecera de features/windows depende de si hay etiquetas). */
int  labels_load(const char *path);
int  labels_enabled(void);

/* Devuelve la regla de la primera etiqueta que encaja, o "benign". */
const char *label_flow(uint32_t src, int64_t first_us, int64_t last_us);
const char *label_window(uint32_t host, int64_t window_start_sec);

#endif
