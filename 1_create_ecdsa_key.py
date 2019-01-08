# Create a Bitcoin EC key pair

from pycryptoki.default_templates import curve_list
from pycryptoki.defines import *  # imports CKA_*s
from pycryptoki.key_generator import *
from pycryptoki.session_management import *
from pycryptoki.encryption import *


c_initialize_ex()
auth_session = c_open_session_ex(3)  # HSM slot # in this example is 3
login_ex(
    auth_session, 3, "crypto-officer-pin"
)  # 3 is still the slot number, ´crypto-officer-pin´ should be replaced by your Crypto Officer password (None if PED or no challenge)

# Make default template for a Bitcoin EC key pair:
CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP = {
    CKA_TOKEN: True,
    CKA_PRIVATE: True,
    CKA_ENCRYPT: True,
    CKA_VERIFY: True,
    CKA_DERIVE: True,
    CKA_ECDSA_PARAMS: curve_list["secp256k1"],
    CKA_LABEL: b"ECDSA Bitcoin Public Key",
}

CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP = {
    CKA_TOKEN: True,
    CKA_PRIVATE: True,
    CKA_SENSITIVE: True,
    CKA_DECRYPT: True,
    CKA_SIGN: True,
    CKA_DERIVE: True,
    CKA_EXTRACTABLE: True,
    CKA_LABEL: b"ECDSA Bitcoin Private Key",
}

# Templates are simple python dictionaries, and can be modified to suit needs.
pub_template, priv_template = (
    CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP,
    CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP,
)

# Modifying the template would look like this:
# pub_template[CKA_LABEL] = "ECDSA Bitcoin Public Key - changed label"
# pub_template[CKA_ECDSA_PARAMS] = curve_list["secp256k1"]  # secp256k1: Bitcoin curve
# priv_template[CKA_LABEL] = "ECDSA Bitcoin Private Key - changed label"

# Generating the key pair:
pubkey, privkey = c_generate_key_pair_ex(
    auth_session, CKM_EC_KEY_PAIR_GEN, pub_template, priv_template
)
# pubkey and privkey contain the handle for both the public and private key.
# Note: We could also use the mechanism CKM_ECDSA_KEY_PAIR_GEN, however as
# per Cryptoki v2.11 this mechanism is deprecated:
# https://www.cryptsoft.com/pkcs11doc/v230/group__SEC__11__3__1__EC__SIGNATURES.html
print("Generated Private key at %s and Public key at %s" % (privkey, pubkey))

c_logout_ex(auth_session)
c_close_session_ex(auth_session)
c_finalize_ex()
