{
    # cliente manda version y metodos que soporta
    # cliente manda usuario y password
    # cliente manda request a google.com
    sleep 0.3; printf '\x05\x03\x00\x01\x02\x01\x08\x6a\x6f\x68\x6e\x5f\x64\x6f\x65\x04\x31\x32\x33\x34\x05\x01\x00\x03\x0a\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d\x00\x50'
    # HTTP GET dos veces
    sleep 0.3; printf 'GET / HTTP/1.1\r\nHost: google.com\r\n\r\nGET / HTTP/1.1\r\nHost: google.com\r\n\r\n'
} | nc localhost 1024 | hexdump -C
while true; do
    cat /dev/random | nc localhost 1024
done
