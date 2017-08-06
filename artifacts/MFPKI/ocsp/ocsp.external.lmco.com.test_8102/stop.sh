
#!/bin/bash

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

OCSP_ROOT=${SCRIPTDIR}
OSSL=${SCRIPTDIR}/../openssl
DAEMONIZE=daemonize

kill `cat $OCSP_ROOT/server.pid`

