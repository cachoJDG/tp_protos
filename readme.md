# Proxy Socksv5 - TPE de Protocolos de Comunicación

## Equipo - Grupo 20

- Javier Emmanuel Liu (jaliu@itba.edu.ar)
- Juan Pablo Birsa (jbirsa@itba.edu.ar)
- Juan Diego Gago (jgago@itba.edu.ar)
- Alex Kenzo Köhler (akohler@itba.edu.ar)

## Implementaciones

1. **Proxy socks5**
    - Soporta autenticación (opcional)
    - Soporta fragmentación y pipelining
    - Solo soporta el comando CONNECT
2. **Servidor y protocolo de monitoreo** (binario)
    - Observar las metricas del Proxy sock5
    - Agregar usuarios
    - Mostrar usuarios
    - Cambiar la contraseña de un usuario
    - Cambiar los roles de un usuario (ADMIN o USER)
    - Eliminar usuarios
    - Soporta fragmentación y pipelining
    - etc.
3. **Cliente** para hacer envíos con el protocolo de monitoreo

## Requisitos

- Make
- GCC

## Compilación

```
make all
```

## Ejecución del servidor

NOTA: El servidor abre 2 puertos: uno para el proxy SOCKS5 y otro para el monitoreo.

**Uso:** ./bin/socks5v [opciones...]

**Opciones:**

    -h               Imprime la ayuda y termina.
    -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.
    -L <conf  addr>  Dirección donde servirá el servicio de management.
    -p <SOCKS port>  Puerto entrante conexiones SOCKS.
    -P <conf port>   Puerto entrante conexiones configuracion
    -u <name>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.
    -v               Imprime información sobre la versión versión y termina. 

### Ejemplos de ejecución (proxy SOCKS5)

NOTA: Ver informe para más información sobre pruebas de ejecución

- **pedido HTTP con usuario y contraseña**
```
curl -x socks5h://john:doe@127.0.0.1:2021 http://example.org
```

- **Envío de datos fragmentados** (el proxy debe estar en el puerto 1080)
```
python3 src/python_tests/socks5_fragmented.py
```

- **Envío de datos combinados** (el proxy debe estar en el puerto 1080)
```
python3 src/python_tests/socks5_combined.py
```

## Protocolo de monitoreo

Detallado en docs/informe.pdf

## Cliente de monitoreo

NOTA: El cliente envía datos al puerto de monitoreo utilizando la sesión que se encuentra en la variable de entorno ```MONITORING_TOKEN``` (con la sintaxis ```usuario:contraseña```)

**Uso:** ./bin/client \<puerto> \<comando> [args...]

**Comandos con argumentos:**
```
    LIST USERS
    ADD USER <username> <password>
    REMOVE USER <username>
    CHANGE PASSWORD <username> <newpassword>
    GET METRICS
    CHANGE ROLE <username> <newrole>
```

### Ejemplos de ejecución

- Llamar funciones del cliente

```
./bin/client 2022 GET METRICS
./bin/client 2022 LIST USERS
./bin/client 2022 ADD USER protosmaster52 1234
```

- **Envío de datos fragmentados** (el servicio de monitoreo debe estar en el puerto 2022)
```
python3 src/python_tests/monitoring_fragmented.py
```

- **Envío de datos combinados** (el servicio de monitoreo debe estar en el puerto 2022)
```
python3 src/python_tests/monitoring_combined.py
```

## Ejemplo completo de corrida

1. Compilación

```
make all
```

2. Ejecución del proxy socks5v (en una terminal aparte)

```
./bin/socks5v -p 2021 -P 2022 -u john:doe
```

3. Exportar token de monitoreo

```
export MONITORING_TOKEN="john:doe"
```

NOTA: el usuario debe estar en la lista de usuarios (Ver paso anterior). Este será el usuario utilizado por ```./bin/client``` para mandar pedidos de monitoreo

4. Configurar proxy para Firefox (buscar "socks" en el menú de configuración)

5. Analizar proxy

```
./bin/client 2022 GET METRICS
```
