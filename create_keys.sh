#!/usr/bin/env bash

#Creating JWT keys
openssl genrsa -out jwtpriv.pem 4096
openssl rsa -in jwtpriv.pem -pubout -out jwtpub.pem

#Creating HTTPS key and cert
openssl genrsa -out server.key 4096
openssl req -new -x509 -sha512 -key server.key -out server.crt -days 3650

