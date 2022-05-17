# openssl-goproxy-sslv3
openssl goproxy sslv3
```
./build.sh
LD_PRELOAD="./openssl-source/dist/lib/libssl.so ./openssl-source/dist/lib/libcrypto.so" ./app
curl -x http://127.0.0.1:8081 https://megadomain.vnn.vn -k
```
