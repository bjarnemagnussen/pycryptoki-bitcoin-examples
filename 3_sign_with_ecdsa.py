# Sign a preimage

from pycryptoki.conversions import to_bytestring, from_hex
from pycryptoki.defines import *  # imports CKA_*s
from pycryptoki.object_attr_lookup import c_find_objects_ex
from pycryptoki.session_management import *
from pycryptoki.sign_verify import c_sign_ex


c_initialize_ex()
auth_session = c_open_session_ex(3)  # HSM slot # in this example is 3
login_ex(
    auth_session, 3, "crypto-user-pin", user_type=2147483649
)
# 3 is still the slot number, ´crypto-user-pin´ should be replaced by your
# Crypto User password (None if PED or no challenge), user_type 2147483649
# (0x80000001) corresponds to the (limited) Crypto User, see:
# https://github.com/gemalto/pycryptoki/issues/13

# Find the private key:
search_template = {CKA_LABEL: b"1BTC Private"}
keys = c_find_objects_ex(auth_session, search_template, 1)
prv_key = keys.pop(0)  # Use the first key found.

# If the data to be signed is in hex format (e.g. preimage for Bitcoin tx):
# raw_data = "95e28bc6da451f3064d688dd283c5c43a5dd374cb21064df836e2970e1024c2448f129062aacbae3e45abd098b893346"
# Convert to raw bytes before passing into c_decrypt:
# data_to_sign = to_bytestring(from_hex(raw_data))
# Instead using the preimage as bytes directly:
data_to_sign = b'_\x97\xbd\xcd\x1c\xb7A5\xcd\xcc\x87h\xbf`@n\xae\xab\xe4\xe8\\jkW\x1a\xb9^\x81Z\xd3\x96X'

# Using the deterministic ECDSA scheme, which is not FIPS certified (needs the
# HSM to be instantiated as non-FIPS!):
# TODO: Not really sure about the algorithm the mechanism CKM_ECDSA_GBCS_SHA256
# is based on!
signature = c_sign_ex(auth_session, prv_key, data_to_sign, mechanism=CKM_ECDSA_GBCS_SHA256)
# Alternative mechanism that is FIPS certified, but non-deterministic:
# signature = c_sign_ex(auth_session, prv_key, data_to_sign, mechanism=CKM_ECDSA_SHA256)

# We don't need to have an open session anymore:
c_logout_ex(auth_session)
c_close_session_ex(auth_session)
c_finalize_ex()

print("Signature (r|s):")
print(signature)
# The calculated signature simply consists of r|s concatenated, each with 32 bytes:
# https://www.cryptsoft.com/pkcs11doc/v220/group__SEC__12__3__1__EC__SIGNATURES.html

# Converting signature to DER encoding used in Bitcoin:
# https://crypto.stackexchange.com/questions/1795/how-can-i-convert-a-der-ecdsa-signature-to-asn-1
# https://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long

# Convert bytes to int:
r_int = int.from_bytes(signature[:32], byteorder='big')  # r as int
s_int = int.from_bytes(signature[32:], byteorder='big')  # s as int

# Make sure that n2 (s) is not "unnecessarily high":
# https://bitcoin.stackexchange.com/questions/68254/how-can-i-fix-this-non-canonical-signature-s-value-is-unnecessarily-high
# N is the order of the secp256k1 elliptic curve:
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
if s_int > N // 2:
    s_int = N - s_int

# r and s are encoded as signed big-endian integer of minimal length:
r = (r_int).to_bytes((r_int).bit_length() // 8 + 1, byteorder='big')
s = (s_int).to_bytes((s_int).bit_length() // 8 + 1, byteorder='big')
b2 = len(r)
b3 = len(s)
b1 = (4 + b2 + b3).to_bytes(1, byteorder="big")

der = (
    bytes.fromhex("30")    # A header byte indicating a compound structure
    + b1                   # A 1-byte length descriptor for all what follows
    + bytes.fromhex("02")  # A header byte indicating an integer
    + b2.to_bytes(1, byteorder="big")  # A 1-byte length descriptor for the R value
    + r                    # The R coordinate, as a big-endian integer
    + bytes.fromhex("02")  # A header byte indicating an integer
    + b3.to_bytes(1, byteorder="big")  # A 1-byte length descriptor for the S value
    + s                    # The S coordinate, as a big-endian integer
)

print("DER encoding (including prepended script push OP):")
print("{:02x}".format(len(der) + 1) + der.hex() + "01")
print("Signature length in decimal: {}".format(len(der) + 1))
