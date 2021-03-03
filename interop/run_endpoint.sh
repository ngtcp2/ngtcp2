#!/bin/bash

# Set up the routing needed for the simulation
/setup.sh

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters

case $TESTCASE in
    versionnegotiation|handshake|transfer|retry|resumption|http3|multiconnect|zerortt|chacha20|keyupdate|ecn)
	:
	;;
    *)
	exit 127
	;;
esac

LOG=/logs/log.txt

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    REQS=($REQUESTS)
    SERVER=$(echo ${REQS[0]} | sed -re 's|^https://([^/:]+)(:[0-9]+)?/.*$|\1|')
    if [ "$TESTCASE" == "http3" ]; then
	CLIENT_BIN="/usr/local/bin/client"
    else
	CLIENT_BIN="/usr/local/bin/h09client"
    fi
    CLIENT_ARGS="$SERVER 443 --download /downloads -s --no-quic-dump --no-http-dump --exit-on-all-streams-close --qlog-dir $QLOGDIR"
    if [ "$TESTCASE" == "versionnegotiation" ]; then
        CLIENT_ARGS="$CLIENT_ARGS -v 0xaaaaaaaa"
    else
	CLIENT_ARGS="$CLIENT_ARGS -v 0x1"
    fi
    if [ "$TESTCASE" == "chacha20" ]; then
	CLIENT_ARGS="$CLIENT_ARGS --ciphers=TLS_CHACHA20_POLY1305_SHA256"
    fi
    if [ "$TESTCASE" == "keyupdate" ]; then
	CLIENT_ARGS="$CLIENT_ARGS --delay-stream 10ms --key-update 1ms"
    fi
    if [ "$TESTCASE" == "resumption" ] || [ "$TESTCASE" == "zerortt" ]; then
	CLIENT_ARGS="$CLIENT_ARGS --session-file session.txt --tp-file tp.txt"
	if [ "$TESTCASE" == "resumption" ]; then
	    CLIENT_ARGS="$CLIENT_ARGS --disable-early-data"
	fi
	REQUESTS=${REQS[0]}
	$CLIENT_BIN $CLIENT_ARGS $REQUESTS $CLIENT_PARAMS &> $LOG
	REQUESTS=${REQS[@]:1}
	$CLIENT_BIN $CLIENT_ARGS $REQUESTS $CLIENT_PARAMS &>> $LOG
    elif [ "$TESTCASE" == "multiconnect" ]; then
	CLIENT_ARGS="$CLIENT_ARGS --timeout=180s"
	for REQ in $REQUESTS; do
	    echo "multiconnect REQ: $REQ" >> $LOG
	    $CLIENT_BIN $CLIENT_ARGS $REQ $CLIENT_PARAMS &>> $LOG
	done
    else
	$CLIENT_BIN $CLIENT_ARGS $REQUESTS $CLIENT_PARAMS &> $LOG
    fi
elif [ "$ROLE" == "server" ]; then
    if [ "$TESTCASE" == "http3" ]; then
	SERVER_BIN="/usr/local/bin/server"
    else
	SERVER_BIN="/usr/local/bin/h09server"
    fi
    SERVER_ARGS="/certs/priv.key /certs/cert.pem -s -d /www --qlog-dir $QLOGDIR"
    if [ "$TESTCASE" == "retry" ]; then
	SERVER_ARGS="$SERVER_ARGS -V"
    elif [ "$TESTCASE" == "multiconnect" ]; then
	SERVER_ARGS="$SERVER_ARGS --timeout=180s"
    fi

    $SERVER_BIN '*' 443 $SERVER_ARGS $SERVER_PARAMS &> $LOG
fi
