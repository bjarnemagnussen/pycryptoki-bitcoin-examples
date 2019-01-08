from pycryptoki.session_management import (c_initialize_ex,
                                           c_get_info_ex,
                                           c_get_slot_list_ex,
                                           get_firmware_version,
                                           c_get_token_info_ex,
                                           c_finalize_ex)


c_initialize_ex()
print("C_GetInfo: ")
print("\n".join("\t{}: {}".format(x, y) for x, y in c_get_info_ex().items()))
slot_list = c_get_slot_list_ex()
print("C_GetSlotList:")
print("\n".join("\t{}".format(x) for x in slot_list))
# Use the first available Slot ID:
slot_id = slot_list[0]
token_info = c_get_token_info_ex(slot_id)
print("C_GetTokenInfo:")
print("\n".join("\t{}: {}".format(x, y) for x, y in token_info.items()))
print("Firmware version: {}".format(get_firmware_version(slot_id)))

c_finalize_ex()
