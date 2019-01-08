# Delete a key

from pycryptoki.session_management import *
from pycryptoki.defines import *  # imports CKA_*s
from pycryptoki.object_attr_lookup import c_find_objects_ex
from pycryptoki.key_generator import c_destroy_object_ex

c_initialize_ex()
auth_session = c_open_session_ex(3)  # HSM slot # in this example is 3
login_ex(
    auth_session, 3, "crypto-officer-pin"
)  # 3 is still the slot number, ´crypto-officer-pin´ should be replaced by your Crypto Officer password (None if PED or no challenge)

# The label/search string to find private key:
search_template = {
    CKA_LABEL: b"1BTC Private"
}

# Delete all keys found with the search:
keys = c_find_objects_ex(auth_session, search_template, 1)
print(keys)
key = keys.pop(0)
c_destroy_object_ex(auth_session, key)

# Deleting the public key
search_template = {
    CKA_LABEL: b"1BTC Public"
}
keys = c_find_objects_ex(auth_session, search_template, 1)
print(keys)
key = keys.pop(0)
c_destroy_object_ex(auth_session, key)

print('Key(s) deleted')

c_logout_ex(auth_session)
c_close_session_ex(auth_session)
c_finalize_ex()
