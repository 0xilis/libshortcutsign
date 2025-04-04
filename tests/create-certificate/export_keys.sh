# Export Private Key (not working atm)

openssl ec -in Snoolie\ Root\ Shortcuts\ Certificate.pem -text > Snoolie\ Root\ Shortcuts\ Certificate-Private.pem
openssl pkey -in Snoolie\ Root\ Shortcuts\ Certificate-Private.pem -out SnoolieRSCPrivateKey.der
# openssl rsa -in Snoolie\ Certificate\ Authority.key -text > SnoolieCertificateAuthority-Private.pem

# Export Public Keys

openssl x509 -inform PEM -in SnoolieRSC.crt > SnoolieRSC-Public.pem
openssl x509 -inform PEM -in Snoolie\ Certificate\ Authority.crt > Snoolie\ Certificate\ Authority-Public.pem


# The Public Key can be added to macOS as:
# sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" Snoolie\ Certificate\ Authority-Public.pem