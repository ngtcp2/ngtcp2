#!/bin/bash

# Set up the routing needed for the simulation
/setup.sh

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters

case $TESTCASE in
    versionnegotiation|handshake|transfer|retry|resumption|http3|multiconnect|zerortt)
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
    CLIENT_ARGS="server 443 --download /downloads -s --no-quic-dump --no-http-dump --timeout=5s"
    if [ "$TESTCASE" == "versionnegotiation" ]; then
        CLIENT_ARGS="$CLIENT_ARGS -v 0xaaaaaaaa"
    fi
    if [ "$TESTCASE" == "resumption" ] || [ "$TESTCASE" == "zerortt" ]; then
	CLIENT_ARGS="$CLIENT_ARGS --session-file session.txt --tp-file tp.txt"
	if [ "$TESTCASE" == "resumption" ]; then
	    CLIENT_ARGS="$CLIENT_ARGS --disable-early-data"
	fi
	REQS=($REQUESTS)
	REQUESTS=${REQS[0]}
	/usr/local/bin/client $CLIENT_ARGS --exit-on-first-stream-close $REQUESTS $CLIENT_PARAMS &> $LOG
	REQUESTS=${REQS[@]:1}
	/usr/local/bin/client $CLIENT_ARGS $REQUESTS $CLIENT_PARAMS &> $LOG
    elif [ "$TESTCASE" == "multiconnect" ]; then
	CLIENT_ARGS="$CLIENT_ARGS --exit-on-first-stream-close --timeout=180s"
	for REQ in $REQUESTS; do
	    echo "multiconnect REQ: $REQ" >> $LOG
	    /usr/local/bin/client $CLIENT_ARGS $REQ $CLIENT_PARAMS &>> $LOG
	done
    else
	/usr/local/bin/client $CLIENT_ARGS $REQUESTS $CLIENT_PARAMS &> $LOG
    fi
elif [ "$ROLE" == "server" ]; then
    SERVER_ARGS="0.0.0.0 443 /etc/ngtcp2/server.key /etc/ngtcp2/server.crt -s -d /www"
    if [ "$TESTCASE" == "retry" ]; then
	SERVER_ARGS="$SERVER_ARGS -V"
    elif [ "$TESTCASE" == "multiconnect" ]; then
	SERVER_ARGS="$SERVER_ARGS --timeout=180s"
    fi

    /usr/local/bin/server $SERVER_ARGS $SERVER_PARAMS &> $LOG
fi
