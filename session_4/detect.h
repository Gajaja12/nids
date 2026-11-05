#ifndef DETECT_H
#define DETECT_H

#include <stdint.h>
#include <stddef.h>

/* Lee la configuracion y abre alerts.csv. Devuelve 0 si todo va bien.
   conf_explicit = 1 si el usuario pidio el fichero con --conf (entonces que
   no exista es un error; con el nombre por defecto se usan los valores de
   serie y se avisa por stderr). */
int  detect_open(const char *alerts_path, const char *conf_path, int conf_explicit);

/* Reglas de ventana: se llama con CADA fila de windows.csv al producirla. */
void detect_window(int64_t window_start, uint32_t host, size_t dst_hosts,
                   unsigned dst_ports, unsigned syn_sent, unsigned unanswered);

/* Se llama al cerrar cada flujo: recuerda su instante de inicio. */
void detect_flow(uint32_t src, uint32_t dst, uint16_t dport, uint8_t proto,
                 int64_t start_us);

/* Fin de captura: ejecuta la regla beacon y cierra alerts.csv. */
void detect_finish(void);

#endif
