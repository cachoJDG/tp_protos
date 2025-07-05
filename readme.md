# Entrega Simulacro para Protocolos de Comunicación

## Implementaciones

1. **Proxy socks5**
    - Acepta login (opcional)
    - Acepta fragmentación hasta cierto punto
    - Acepta combinación de paquetes hasta cierto punto
2. **Protocolo de monitoreo** (binario)
    - Agregar usuarios
    - Mostrar usuarios
    - etc.
3. **Cliente** para hacer envíos con el protocolo de monitoreo

## Comandos del cliente

Usage: ./bin/client \<server> \<port> \<command> [args...]

    LIST USERS
    ADD USER <username> <password>
    REMOVE USER <username>
    CHANGE PASSWORD <username> <newpassword>
    GET METRICS

## Protocolo de monitoreo

Comming soon

## Comandos del servidor

Usage: ./bin/socks5v [OPTION]...

    -h               Imprime la ayuda y termina.
    -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.
    -L <conf  addr>  Dirección donde servirá el servicio de management.
    -p <SOCKS port>  Puerto entrante conexiones SOCKS.
    -P <conf port>   Puerto entrante conexiones configuracion
    -u <name>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.
    -v               Imprime información sobre la versión versión y termina. 

## Ejemplo de corrida

1. Compilación

```
make all
```

2. Ejecución del proxy socks5v

```
./bin/socks5v -p 2021 -P 2022 -u john_doe:1234
```

3. Testeos de python (hechos con IA) para fragmentación y combinación de paquetes

```
python3 src/python_tests/socks5_combined.py
python3 src/python_tests/socks5_fragmented.py
```

NOTA: los scripts de python se rompen en cierto momento, pero aún así hay ciertas funcionalidades que funcionan bien. Importante que el puerto del server sea 2021

4. Usar como proxy para Chrome (depende de cada máquina)

NOTA: A veces tira aborts o cosas raras en páginas pesadas como Fandom, pero a nosotros nos funcionó bastante bien

5. Exportar token de monitoreo

```
export MONITORING_TOKEN="john_doe|1234"
```

NOTA: el usuario debe estar en la lista de usuarios

6. Llamar funciones del cliente

```
./bin/client 127.0.0.1 2022 LIST USERS
./bin/client 127.0.0.1 2022 ADD USER protosmaster52 1234
```









