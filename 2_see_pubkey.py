# See public key and change label correspondingly

from pycryptoki.cryptoki import CK_ULONG, CK_BYTE
from pycryptoki.session_management import *
from pycryptoki.defines import *  # imports CKA_*s
from pycryptoki.object_attr_lookup import (
    c_find_objects_ex, c_get_attribute_value_ex, c_set_attribute_value_ex
)

c_initialize_ex()
auth_session = c_open_session_ex(3)  # HSM slot # in this example is 3
login_ex(
    auth_session, 3, "crypto-officer-pin"
)  # 3 is still the slot number, ´crypto-officer-pin´ should be replaced by your Crypto Officer password (None if PED or no challenge)
# Remark: To retrieve the public key we could also login as the Crypto User
# (3_see sign_with_ecdsa.py). However, in this example we also want to change
# the label and therefore need the permission of the Crypto Officer.

# The label/search string to find key:
search_template = {
    CKA_LABEL: b"ECDSA Bitcoin Public Key"  # E.g. the newly created key
}

# Find the key with the search:
keys = c_find_objects_ex(auth_session, search_template, 1)
prv_key = keys.pop(0)  # Use the first (and only) key found.

# For retrieving attributes we just set the value to of the attribute to None.
# Pycryptoki will then figure out the length for that attribute used as a
# buffer that is overwritten with the found value:
attribute_template = {
    CKA_EC_POINT: None
}
result_pub = c_get_attribute_value_ex(auth_session, prv_key, attribute_template)
# The stored attribute is an uncompressed public key using "DER-encoding of
# ANSI X9.62 ECPoint value Q"with the last to bytes representing, see:
# https://www.cryptsoft.com/pkcs11doc/v220/group__SEC__12__3__3__ECDSA__PUBLIC__KEY__OBJECTS.html
# However, the first two bytes represent something (e.g. the curve used, etc.)
# which I don't know what is an must be trimmed to get the uncompressed
# public key used with Bitcoin.
pub_key = result_pub[CKA_EC_POINT][4:]  # We trim the first two bytes
print('Uncompressed public key:')
print(pub_key)

# TODO: Convert the uncompressed public key to compressed public key

# TODO: Convert the public key to address
address = b'1BTC'

# Optional: Update the label for both the public and private key:
search_template = {
    CKA_EC_POINT: result_pub[CKA_EC_POINT]
}  # Will find exactly two keys: the private and the public key
keys = c_find_objects_ex(auth_session, search_template, 2)
for key in keys:
    attribute_template = {
        CKA_CLASS: None
    }
    result = c_get_attribute_value_ex(auth_session, key, attribute_template)
    # Change labels:
    if result[CKA_CLASS] == CKO_PRIVATE_KEY:
        # Private key:
        c_set_attribute_value_ex(auth_session, key, {CKA_LABEL: address + b' Private'})
    elif result[CKA_CLASS] == CKO_PUBLIC_KEY:
        # Public key:
        c_set_attribute_value_ex(auth_session, key, {CKA_LABEL: address + b' Public'})


c_logout_ex(auth_session)
c_close_session_ex(auth_session)
c_finalize_ex()
