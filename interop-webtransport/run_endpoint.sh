#!/bin/bash

# Set up the routing needed for the simulation
/setup.sh

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters

LOG=/logs/log.txt

if [ "$ROLE" == "client" ]; then
    CLIENT_BIN="/usr/local/bin/bsslwtclient"
    CLIENT_ARGS="--webtransport-interop --htdocs /www --download /downloads --qlog-dir $QLOGDIR --show-stat --no-quic-dump --no-http-dump"

    $CLIENT_BIN $CLIENT_ARGS &> $LOG
else
    SERVER_BIN="/usr/local/bin/bsslwtserver"
    SERVER_ARGS="/certs/priv.key /certs/cert.pem --webtransport-interop -d /www --download /downloads --qlog-dir $QLOGDIR --show-stat --no-quic-dump --no-http-dump"

    $SERVER_BIN '*' 443 $SERVER_ARGS &> $LOG
fi
