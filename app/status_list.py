"""
Bitstring Status List — revocation for offline-verifiable credentials.

The jwt_vc / sd_jwt_vc formats are verified offline (signature + cnf binding, no
call back to the registry).  That makes them un-revocable on their own: a revoked
agent's previously-issued JWT stays cryptographically valid forever.

A Status List closes that gap.  The registry publishes one signed credential — a
compressed bitstring where each agent owns one bit — at a stable URL.  Every
issued charter carries a ``credentialStatus`` pointing at its bit.  An offline
verifier fetches the list once (cacheable), checks the bit, and learns whether the
credential is revoked without the registry vouching per-credential.

Implements W3C Bitstring Status List v1.0:
  https://www.w3.org/TR/vc-bitstring-status-list/

The bitstring is *derived* from the Agent table (bit = 1 ⇔ agent revoked) rather
than stored, so the published list can never drift from the source of truth.
"""
import gzip

from app.crypto import b64url_encode

# Spec minimum: 131072 bits (16 KB) for herd privacy.
STATUS_LIST_BITS = 131_072
STATUS_LIST_BYTES = STATUS_LIST_BITS // 8


def build_encoded_list(revoked_indices: list[int]) -> str:
    """
    Build the multibase-encoded, GZIP-compressed bitstring.

    Bit order per spec: index *i* is the (i % 8)-th bit from the **most**
    significant end of byte *i // 8*.  Returns a 'u'-prefixed base64url string
    (multibase) as required for the ``encodedList`` property.
    """
    bits = bytearray(STATUS_LIST_BYTES)
    for i in revoked_indices:
        if 0 <= i < STATUS_LIST_BITS:
            bits[i // 8] |= 0b1000_0000 >> (i % 8)
    compressed = gzip.compress(bytes(bits))
    return "u" + b64url_encode(compressed)


def status_list_credential(
    issuer_did: str,
    list_url: str,
    encoded_list: str,
    valid_from: str,
) -> dict:
    """Assemble an unsigned BitstringStatusListCredential (caller signs it)."""
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": list_url,
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": issuer_did,
        "validFrom": valid_from,
        "credentialSubject": {
            "id": f"{list_url}#list",
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": encoded_list,
        },
    }


def credential_status_entry(list_url: str, index: int) -> dict:
    """The ``credentialStatus`` object embedded in each issued charter."""
    return {
        "id": f"{list_url}#{index}",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": str(index),
        "statusListCredential": list_url,
    }
