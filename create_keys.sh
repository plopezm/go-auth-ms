#!/usr/bin/env bash

openssl genrsa -out privkey.pem 4096
openssl rsa -in privkey.pem -pubout -out pubkey.pem
