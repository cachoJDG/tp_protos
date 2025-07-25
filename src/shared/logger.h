#ifndef __logger_h_
#define __logger_h_
#include <stdio.h>
#include <stdlib.h>

/* 
*  Macros y funciones simples para log de errores.
*  EL log se hace en forma simple
*  Alternativa: usar syslog para un log mas completo. Ver sección 13.4 del libro de  Stevens
*/

typedef enum {DEBUG=0, INFO, ERROR, FATAL} LOG_LEVEL;

extern LOG_LEVEL current_level;

extern FILE *log_file;

/**
*  Minimo nivel de log a registrar. Cualquier llamada a log con un nivel mayor a newLevel sera ignorada
**/
void setLogLevel(LOG_LEVEL newLevel);

char * levelDescription(LOG_LEVEL level);
char * levelDescriptionPlain(LOG_LEVEL level);

void setLogFile(const char *filename);

// Debe ser una macro para poder obtener nombre y linea de archivo. 
#define log(level, fmt, ...)   {if(level >= current_level) {\
    fprintf (stderr, "%s %s [%s] %s:%d, ",__DATE__, __TIME__, levelDescription(level), __FILE__, __LINE__); \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    fprintf(stderr,"\n"); \
    if (log_file != NULL) { \
        fprintf (log_file, "%s %s [%s] %s:%d, ",__DATE__, __TIME__, levelDescriptionPlain(level), __FILE__, __LINE__); \
        fprintf(log_file, fmt, ##__VA_ARGS__); \
        fprintf(log_file,"\n"); \
    } \
	} \
    if ( level==FATAL) exit(1);}
#endif
