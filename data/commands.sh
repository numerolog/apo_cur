openssl genpkey -algorithm RSA -out sender_priv.pem -pkeyopt rsa_keygen_bits:4096 || exit 1
openssl rsa -in sender_priv.pem -pubout > sender_pub.pem || exit 2

openssl genpkey -algorithm RSA -out recv_priv.pem -pkeyopt rsa_keygen_bits:4096 || exit 1
openssl rsa -in recv_priv.pem -pubout > recv_pub.pem || exit 2
#openssl req -new -x509 -key priv.pem -out cert.pem -days 99999 || exit 3


