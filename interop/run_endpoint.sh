#!/bin/bash

# Set up the routing needed for the simulation
/setup.sh

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters

case $TESTCASE in
    versionnegotiation|handshake|transfer|retry|resumption|http3)
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
    CLIENT_ARGS="server 443 --download /downloads -s --no-quic-dump --no-http-dump"
    if [ "$TESTCASE" == "versionnegotiation" ]; then
        CLIENT_ARGS="$CLIENT_ARGS -v 0xaaaaaaaa"
    fi
    if [ "$TESTCASE" == "resumption" ]; then
	CLIENT_ARGS="$CLIENT_ARGS --session-file session.txt --tp-file tp.txt"
	REQS=($REQUESTS)
	REQUESTS=${REQS[0]}
	/usr/local/bin/client $CLIENT_ARGS $REQUESTS $CLIENT_PARAMS &> $LOG
	REQUESTS=${REQS[@]:1}
	/usr/local/bin/client $CLIENT_ARGS $REQUESTS $CLIENT_PARAMS &> $LOG
    else
	/usr/local/bin/client $CLIENT_ARGS $REQUESTS $CLIENT_PARAMS &> $LOG
    fi
elif [ "$ROLE" == "server" ]; then
    SERVER_ARGS="0.0.0.0 443 /etc/ngtcp2/server.key /etc/ngtcp2/server.crt -s -d /www"
    if [ "$TESTCASE" == "retry" ]; then
	SERVER_ARGS="$SERVER_ARGS -V"
    fi
    /usr/local/bin/server $SERVER_ARGS $SERVER_PARAMS &> $LOG
fi
