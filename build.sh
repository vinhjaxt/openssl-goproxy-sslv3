sudo rm -rf /usr/include/x86_64-linux-gnu/openssl /usr/local/ssl/include/openssl 
sudo mkdir -p /usr/local/ssl/include /usr/local/ssl/lib
sudo cp --remove-destination -r ./openssl-source/dist/include/openssl /usr/include/x86_64-linux-gnu/openssl/
sudo cp --remove-destination -r ./openssl-source/dist/lib/* /usr/lib/x86_64-linux-gnu/
sudo cp --remove-destination -r ./openssl-source/dist/include/openssl /usr/local/ssl/include/
sudo cp --remove-destination -r ./openssl-source/dist/lib/* /usr/local/ssl/lib/
CGO_LDFLAGS="-g -O2 -L /usr/local/ssl/lib/ -ldl" GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -v ./...
