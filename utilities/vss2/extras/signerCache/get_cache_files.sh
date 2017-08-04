
#Delete existing PEM

/bin/rm *.pem


#Prod

/usr/bin/wget http://pki.treasury.gov/VSSignerCertCache.pem.gz
/usr/bin/wget http://pki.treasury.gov/VSHASignerCertCache.pem.gz
/usr/bin/wget http://pki.treasury.gov/VSKCSignerCertCache.pem.gz
/usr/bin/wget http://pki.treasury.gov/VSKCHASignerCertCache.pem.gz

#Dev

/usr/bin/wget http://devpki.treasury.gov/vss/devVSSCertCache.pem.gz

#Un-compress

/bin/gunzip *.gz