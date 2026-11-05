#ifndef DETECT_H
#define DETECT_H

#include <stdint.h>
#include <stddef.h>

/* Lee la configuracion y abre alerts.csv; alerts.txt (incidentes) se escribe al
   final, en txt_path. 0 = ok. conf_explicit = 1 si el usuario dio --conf. */
int  detect_open(const char *alerts_path, const char *txt_path,
                 const char *conf_path, int conf_explicit);

/* Reglas de ventana: se llama con CADA fila de windows.csv al producirla. */
void detect_window(int64_t window_start, uint32_t host, size_t dst_hosts,
                   unsigned dst_ports, unsigned syn_sent, unsigned unanswered);

/* Se llama al cerrar cada flujo: recuerda su instante de inicio. */
void detect_flow(uint32_t src, uint32_t dst, uint16_t dport, uint8_t proto,
                 int64_t start_us);

/* Fin de captura: regla beacon, incidentes (alerts.txt) y cierre de ficheros. */
void detect_finish(void);

/* Para el resumen final (validos tras detect_finish). */
unsigned long long detect_alert_count(void);
unsigned long long detect_incident_count(void);

#endif
