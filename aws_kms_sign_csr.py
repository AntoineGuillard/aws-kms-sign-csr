#!/usr/bin/env python3
"""
python script to re-sign an existing CSR with an asymmetric keypair held in AWS KMS
"""
import hashlib
import base64
import textwrap
import argparse
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
import pyasn1_modules.pem
import pyasn1_modules.rfc2986
import pyasn1_modules.rfc2314
import boto3

START_MARKER = "-----BEGIN CERTIFICATE REQUEST-----"
END_MARKER = "-----END CERTIFICATE REQUEST-----"


def sign_certification_request_info(
    kms, key_id, csr, digest_algorithm, signing_algorithm
):
    certification_request_info = csr["certificationRequestInfo"]
    der_bytes = encoder.encode(certification_request_info)
    digest = hashlib.new(digest_algorithm)
    digest.update(der_bytes)
    digest = digest.digest()
    response = kms.sign(
        KeyId=key_id,
        Message=digest,
        MessageType="DIGEST",
        SigningAlgorithm=signing_algorithm,
    )
    return response["Signature"]


def output_csr(csr):
    print(START_MARKER)
    b64 = base64.b64encode(encoder.encode(csr)).decode("ascii")
    for line in textwrap.wrap(b64, width=64):
        print(line)
    print(END_MARKER)


def signing_algorithm_func(hashalgo, signalgo):
    # Signature Algorithm OIDs retrieved from
    # https://www.ibm.com/docs/en/linux-on-systems?topic=linuxonibm/com.ibm.linux.z.wskc.doc/wskc_pka_pim_restrictions.html
    if hashalgo == "sha512" and signalgo == "ECDSA":
        result = "ECDSA_SHA_512", "1.2.840.10045.4.3.4"
    if hashalgo == "sha384" and signalgo == "ECDSA":
        result = "ECDSA_SHA_384", "1.2.840.10045.4.3.3"
    if hashalgo == "sha256" and signalgo == "ECDSA":
        result = "ECDSA_SHA_256", "1.2.840.10045.4.3.2"
    if hashalgo == "sha224" and signalgo == "ECDSA":
        result = "ECDSA_SHA_224", "1.2.840.10045.4.3.1"
    if hashalgo == "sha512" and signalgo == "RSA":
        result = "RSASSA_PKCS1_V1_5_SHA_512", "1.2.840.113549.1.1.13"
    if hashalgo == "sha384" and signalgo == "RSA":
        result = "RSASSA_PKCS1_V1_5_SHA_384", "1.2.840.113549.1.1.12"
    if hashalgo == "sha256" and signalgo == "RSA":
        result = "RSASSA_PKCS1_V1_5_SHA_256", "1.2.840.113549.1.1.11"
    else:
        raise Exception(
            "unknown hash algorithm,\
                    please specify one of sha224,\
                    sha256, sha384, or sha512"
        )
    return result


def main(args):
    with open(args.csr, "r", encoding="utf-8") as csr_file:
        substrate = pyasn1_modules.pem.readPemFromFile(
            csr_file, startMarker=START_MARKER, endMarker=END_MARKER
        )
        csr = decoder.decode(
            substrate, asn1Spec=pyasn1_modules.rfc2986.CertificationRequest()
        )[0]
        if not csr:
            raise Exception("File does not look like a CSR")

    # now get the key
    if not args.region:
        args.region = boto3.session.Session().region_name

    kms = boto3.client("kms", region_name=args.region)

    response = kms.get_public_key(KeyId=args.keyid)
    pubkey_der = response["PublicKey"]
    csr["certificationRequestInfo"]["subjectPKInfo"] = decoder.decode(
        pubkey_der, pyasn1_modules.rfc2314.SubjectPublicKeyInfo()
    )[0]

    signature_bytes = sign_certification_request_info(
        kms,
        args.keyid,
        csr,
        args.hashalgo,
        signing_algorithm_func(args.hashalgo, args.signalgo)[0],
    )
    csr.setComponentByName("signature", univ.BitString.fromOctetString(signature_bytes))

    sig_algo_identifier = pyasn1_modules.rfc2314.SignatureAlgorithmIdentifier()
    sig_algo_identifier.setComponentByName(
        "algorithm",
        univ.ObjectIdentifier(signing_algorithm_func(args.hashalgo, args.signalgo)[1]),
    )
    csr.setComponentByName("signatureAlgorithm", sig_algo_identifier)

    output_csr(csr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csr", help="Source CSR (can be signed with any key)")
    parser.add_argument(
        "--keyid", action="store", dest="keyid", help="key ID in AWS KMS"
    )
    parser.add_argument("--region", action="store", dest="region", help="AWS region")
    parser.add_argument(
        "--hashalgo",
        choices=["sha224", "sha256", "sha512", "sha384"],
        default="sha256",
        help="hash algorithm to choose",
    )
    parser.add_argument(
        "--signalgo",
        choices=["ECDSA", "RSA"],
        default="RSA",
        help="signing algorithm to choose",
    )
    main(parser.parse_args())
