"""
server parameters
"""
SERVER_VERSION = 3
DEFAULT_PORT = '1357'
PORT_FILE_NAME = 'port.info'
RECEIVE_FILES_FOLDER = 'receive_files'
DEFENSIVE_DB = 'defensive.db'
# kind bytes
STRING_USERNAME = 255
STRING_FILENAME = 255
CHUNK_SIZE = 1024
HEADER_SIZE_RESPONSE = 7
CHECKSUM_SIZE = 4
CONTENT_SIZE = 4
PUBLIC_KEY_SIZE = 160
HEADER_SIZE = 23
UUID_SIZE = 16
EMPTY_PAYLOAD = 0
IV = b'0000000000000000'  # '\0'
CRC_RESPONSE = UUID_SIZE + CONTENT_SIZE + STRING_FILENAME + CHECKSUM_SIZE  # 16+4+255+4
# received
REGISTER_REQUEST_PAYLOAD = STRING_USERNAME + PUBLIC_KEY_SIZE

MAX_CONNECTIONS = 100
# --------------------------------- Server response code ---------------------------------
# Registration request for a new user
REGISTER_REQUEST = 1025
SEND_PUBLIC_KEY = 1026
RELOGIN_REQUEST = 1027
SEND_FILE_REQUEST = 1028
CRC_SUCCESS = 1029
CRC_FAILED = 1030
CRC_FAILED_4 = 1031
# --------------------------------- Server response code ---------------------------------
# Registration was successful If a user is saved in memory, it will return a success answer
REGISTRATION_SUCCESS = 2100
#  Registration was failed ,If a user is not saved in memory, it will return a success answer
REGISTRATION_FAILED = 2101
# Got public key as expected, sending AES key
GOT_PUBLIC_KEY_SEND_AES_KEY = 2102
# File received as expected send CRC
CRC_OK = 2103
# Message confirmation, thank you
MESSAGE_CONFIRMATION = 2104
# AES encrypted sender reconnection request confirmation
CONFIRMS_RETURN_REQUEST = 2105
# Login request rejected
RELOGIN_REQUEST_FAIL = 2106
# General server error
GENERAL_SERVER_ERROR = 2107
