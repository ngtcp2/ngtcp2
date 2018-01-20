#!/bin/sh
# Generate a self-signed certificate for testing purposes.

mkdir -p cert
keyfile=cert/server.key
certfile=cert/server.crt

openssl req -newkey rsa:2048 -x509 -nodes -keyout "$keyfile" -new -out "$certfile" -subj /CN=localhost
