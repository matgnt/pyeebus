from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes, _serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from  cryptography import x509
from cryptography.x509.oid import NameOID


def generate_key(private_key_fn: str, public_key_fn: str = ""):
    """
    SHIP v1.0.1 L 571: secp256r1 curve MUST be used

    Writes private key to `private_key_fn`
    and if `public_key_fn` is given (optional), also public key is written to disk.
    """
    private_key = ec.generate_private_key(ec.SECP256R1)
    private_key_pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=_serialization.NoEncryption(),
        )
    with(open(private_key_fn, 'wb')) as f:
        f.write(private_key_pem_bytes)
    
    if public_key_fn:
        public_key_pem_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with(open(public_key_fn, 'wb')) as f:
            f.write(public_key_pem_bytes)

def generate_x509_keys_by_fn(public_key_pem_fn: str, private_key_pem_fn: str, cert_fn: str = "") -> bytes:
    """
    Wrapper to use keys from files
    """
    public_key = None
    private_key = None
    with(open(public_key_pem_fn, 'rb')) as f:
        public_key = f.read()
    with(open(private_key_pem_fn, 'rb')) as f:
        private_key = f.read()

    return generate_x509(public_key_pem=public_key, private_key_pem=private_key, cert_fn=cert_fn)

def generate_x509(public_key_pem: bytes, private_key_pem: bytes, cert_fn: str = "") -> bytes:
    """
    SHIP v1.0.1 L: 842 and following (SHIP Node Certificates)
    L 875: SHIP nodes should ignore common name field

    Taken from the library's tutorial
    https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate

    cert_fn: write to this file if given
    Returns certificate bytes
    """
    private_key = load_pem_private_key(private_key_pem, password=None)
    public_key = load_pem_public_key(public_key_pem)

    subject = x509.Name(attributes=[
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"), # dummy. is ignored in SHIP protocol
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject # self-signed subject == issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False
    ).add_extension(
        # mandatory for SHIP protocol
        # the method already makes the SHA1 of the public key
        x509.SubjectKeyIdentifier.from_public_key(public_key=public_key),
        critical=False
    ).sign(
        private_key,
        hashes.SHA256()
    )
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    if cert_fn:
        with(open(cert_fn, 'wb')) as f:
            f.write(cert_bytes)

    return cert_bytes

def get_ski_from_pem_crt_file(cert_fn: str):
    cert_bytes = None
    with(open(cert_fn, 'rb')) as f:
        cert_bytes = f.read()
    cert = x509.load_pem_x509_certificate(data=cert_bytes)

    ski_ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    #x = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski_ext.value)
    return ski_ext.value.key_identifier
