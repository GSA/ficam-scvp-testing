
#!/bin/bash

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

TOP=${SCRIPTDIR}

for f in $(find $TOP -name start.sh); do
    echo $f;
    bash $f;
done


