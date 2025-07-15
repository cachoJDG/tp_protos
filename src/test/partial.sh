{
    # cliente manda version y metodos que soporta
    sleep 0.3; printf '\x05'
    sleep 0.3; printf '\x03\x00'
    sleep 0.3; printf '\x01\x02'
    # cliente manda usuario y password
    sleep 0.3; printf '\x01\x08\x6a'
    sleep 0.3; printf '\x6f'
    sleep 0.3; printf '\x68\x6e\x5f'
    sleep 0.3; printf '\x64\x6f\x65\x04\x31\x32\x33\x34'
    # cliente manda request a example.org
    sleep 0.3; printf '\x05\x01'
    sleep 0.3; printf '\x00\x03\x0b\x65\x78\x61'
    sleep 0.3; printf '\x6d\x70\x6c\x65\x2e\x6f\x72\x67\x00\x50'

    # HTTP GET
    sleep 0.3; printf 'GET / HTTP/1.1\r\nHost: example.org\r\n\r\n'
} | nc localhost 1024 | hexdump -C