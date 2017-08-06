
#!/bin/bash

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

OCSP_ROOT=${SCRIPTDIR}
OSSL=${SCRIPTDIR}/../../openssl
DAEMONIZE=daemonize

$DAEMONIZE -c $OCSP_ROOT -a -e $OCSP_ROOT/err.log -o $OCSP_ROOT/out.log -p $OCSP_ROOT/server.pid -l $OCSP_ROOT/server.lck \
    $OSSL ocsp -port 8098 -issuers $OCSP_ROOT/issuers.pem -indexdir $OCSP_ROOT/indexes -rsignerdir $OCSP_ROOT/responder_certs


