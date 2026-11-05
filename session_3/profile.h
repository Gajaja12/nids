#ifndef PROFILE_H
#define PROFILE_H

/* Las 15 features del perfil, en el orden de profile.csv:
   10 de flujo y 5 de ventana (synack_recv se deja fuera). */
enum {
    PF_DURATION, PF_PKTS, PF_BYTES, PF_BYTES_PER_S, PF_PKTS_PER_S,
    PF_FWD_BYTE_SHARE, PF_MEAN_PKT_SIZE, PF_MEAN_IAT, PF_STD_IAT,
    PF_SYN_ONLY_FRAC,
    PF_PKTS_SENT, PF_DST_HOSTS, PF_DST_PORTS, PF_SYN_SENT, PF_UNANSWERED_SYN,
    PF_COUNT
};

int  profile_open(const char *path);   /* activa el perfil; 0 = ok */
int  profile_enabled(void);
void profile_add(int feature, double value);   /* no hace nada si esta apagado */
void profile_finish(void);                     /* escribe profile.csv */

#endif
