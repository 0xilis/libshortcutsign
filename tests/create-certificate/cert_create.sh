# thanks to https://stackoverflow.com/questions/11992036/how-do-i-create-an-ecdsa-certificate-with-the-openssl-command-line

openssl ecparam -genkey -name prime256v1 -noout -out shortcut-sign-test-private.pem

openssl pkey -in shortcut-sign-test-private.pem -outform der -out shortcut-sign-test-private.der

openssl req -key shortcut-sign-test-private.pem -config myconfig.cnf -new -out shortcut-sign-test-private.csr

openssl x509 -signkey shortcut-sign-test-private.pem -in shortcut-sign-test-private.csr -req -days 365 -out shortcut-sign-test-private.crt

# LibreSSL 2 is too old to do this

/usr/local/opt/openssl@3/bin/openssl ecparam -name prime256v1 -genkey -noout -out "shortcut-sign Certificate Authority.key"

/usr/local/opt/openssl@3/bin/openssl req -x509 -sha256 -days 365 -key "shortcut-sign Certificate Authority.key" -out "shortcut-sign Certificate Authority.crt" -config myconfig_ca.cnf

openssl x509 -req -CA shortcut-sign\ Certificate\ Authority.crt -CAkey shortcut-sign\ Certificate\ Authority.key -in shortcut-sign-test-private.csr -out shortcut-sign-test-private.crt -days 365 -CAcreateserial -extfile myconfig.cnf -extensions v3_req