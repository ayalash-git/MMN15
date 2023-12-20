import traceback
from asyncio.windows_events import NULL
from collections import namedtuple
import os
import selectors
import time
import socket
import sqlite3
import struct
import binascii
import uuid
import string
import sys
import Crypto
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from secrets import token_bytes
import zlib
from PortID import PortID
from FileUtils import FileUtils
from Main import *
from ServerConst import *
from cksum import CheckSum

# logger format - print to console
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("debug.log"),
        logging.StreamHandler()
    ]
)


class Server:
    def __init__(self, ip):
        self.ip = ip
        self.logger = logging.getLogger("server")
        self.logger.info(f'Server version {SERVER_VERSION} start running...')
        try:
            self.port = PortID.get_port_id(self)
        except Exception as err:  # if invalid port
            self.logger.exception(f'Error in server __init__: {err}')
            exit(1)
        # version of server
        self.version = SERVER_VERSION
        # Status code after processing the request
        self.answer_code = 0
        self.response_size = 0
        self.current_client_id = b''
        self.AES_key = token_bytes(16)
        # Open the SQL database If they don't exist, create one
        self.connection, self.cursor = self.open_sql_db(self)
        # Create a directory to save received files
        FileUtils.create_directory(self)
        self.sel = selectors.DefaultSelector()
        try:
            # open server socket (TCP/IP non-blocking)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind((self.ip, self.port))
            self.sock.listen(MAX_CONNECTIONS)
            self.sock.setblocking(False)
        except Exception as exp:
            self.close()
            self.logger.fatal(f"Closed server socket because of exception! {exp}, \n {traceback.format_exc()}")
        # Log call events on the server socket
        self.sel.register(self.sock, selectors.EVENT_READ, self.accept)

    def run(self):
        """
        Main server function run the incoming event from client
        :return:
        """
        while True:
            events = self.sel.select()
            for key, mask in events:
                callback = key.data
                self.logger.debug(f'processing new event {key.data}')
                callback(key.fileobj, mask)

    def accept(self, sock, mask):
        """
        Accept connection with given client
        :param sock:
        :param mask:
        :return:
        """
        connection, address = sock.accept()
        # Accepted client from address:
        self.logger.info(f'Client receives an address {address}')
        connection.setblocking(False)
        self.sel.register(connection, selectors.EVENT_READ, self.read)
        self.logger.info('Connects with the client done successful')

    def read(self, connection, mask):
        """
           This function reads the incoming message
           reading and parsing the header and process the matching request (in the header).
           """
        unpack_header = None

        try:
            header = self.receive_header(connection, mask)
            Header = namedtuple('Header',
                                ['ClientID', 'Version', 'req_code', 'PayloadSize'])
            self.logger.info(f"header data size is {len(header)} ")
            unpack_header = Header._make(self.unpack_header(header))
            self.logger.debug(f"request code  {unpack_header.req_code} request size {unpack_header.PayloadSize}")
            self.process_request(connection, mask, unpack_header)

        except Exception as err:
            self.logger.error(f'An unexpected error happened read API : {err}')
            self.answer_code = GENERAL_SERVER_ERROR
            self.response_size = EMPTY_PAYLOAD
            self.close_connection_with_client(connection, unpack_header)

    def process_request(self, connection, mask, uh):
        """
        This function working accordingly to the received request
        send by client , handle the matching request and send a matching response
        uh = unpacked header after named tuple
        """
        self.logger.info(f"process request code {uh.req_code}")
        # 1025
        if uh.req_code == REGISTER_REQUEST:
            self.logger.debug('Register request')
            self.registration_request(connection, mask, uh)
            self.response_registration(connection, mask)
        # 1026
        elif uh.req_code == SEND_PUBLIC_KEY:
            self.logger.debug('Send public key request')
            aes_key = self.receive_public_key(connection, mask, uh)
            self.send_aes_key_response(connection, mask, aes_key)
        # register again 1027
        elif uh.req_code == RELOGIN_REQUEST:
            self.logger.debug('registration request registrant')
            aes_key = self.registration_request_registrant(connection, mask, uh)
            self.login_again_registration_response(connection, mask, aes_key)
        # Request code 1028 send file request
        elif uh.req_code == SEND_FILE_REQUEST:
            self.logger.debug('Send file request')
            upf, crc = self.receiving_file(connection, mask, uh)
            self.response_received_file(connection, mask, upf, crc)
        # 1029
        elif uh.req_code == CRC_SUCCESS:
            self.logger.debug(f'CRC success request , verify the file received from {uh.ClientID}')
            self.verifies_file(connection, mask, uh)
            self.message_confirmation_response(connection, mask, uh)
        # 1030
        elif uh.req_code == CRC_FAILED:
            self.logger.info(f"Got invalid CRC message payload size {uh.PayloadSize} ")
            file_name = self.get_file_name_payload(connection, mask, uh)
            self.logger.debug(f'Invalid CRC , client should send the file {file_name} '
                              f'again using code {SEND_FILE_REQUEST}')
        # CRC fail 4 times 1031
        elif uh.req_code == CRC_FAILED_4:
            self.logger.debug(f'Got invalid CRC four times, close the connection, request code {CRC_FAILED_4}')
            self.message_confirmation_response(connection, mask, uh)
        else:
            self.logger.error(f'Got an unexpected request {uh.req_code} , close connection')
            self.close_connection_with_client(connection, uh.ClientID)

    def registration_request(self, connection, mask, uh):
        """
        This function handles a registration request,
        the payload consists of a public key and a username
        when no errors occurred add the new customer to the database and
        returns the UUID created for the customer and an answer_code update
        """
        payload = self.receive_payload(connection, mask, uh.PayloadSize)
        Payload = namedtuple('Payload', ['username'])
        up = Payload._make(self.parse_payload(payload, username_size=STRING_USERNAME))
        # add new user to database if not exist
        self.add_new_user_to_db(up.username)

    def add_new_user_to_db(self, username):
        """
        A API for add new client to clients DB
        :param username: user name to add
        :return:
        """
        # Searching DB for client existence
        self.logger.debug(f'Search for an existing customer with given name {username} in the DB')
        self.cursor.execute("SELECT Name FROM clients WHERE Name=:name", {"name": username})
        client_name = self.cursor.fetchone()
        if client_name is not None:
            self.logger.info(
                # Returns an error message to the client
                f'Client {client_name[0]} with username {username} already exists,'
                f' registration flow break, send REGISTRATION_FAILED response')
            # failed 2101
            self.answer_code = REGISTRATION_FAILED
            self.response_size = EMPTY_PAYLOAD
        else:
            # Register new client
            uid = uuid.uuid4().bytes_le
            # new client with new uuid
            self.logger.info(f'A new customer {username} registration request, create UUID: {uid}')
            self.cursor.execute("INSERT INTO clients (ID, Name, PublicKey, LastSeen, AES)"
                                " VALUES (?, ?, ?, ?, ?)", (uid, username, NULL, time.ctime(), NULL))
            # Update changes in DB
            self.connection.commit()
            # successfully
            self.answer_code = REGISTRATION_SUCCESS
            self.response_size = UUID_SIZE
            self.current_client_id = uid
            self.logger.info(f'New customer data {username} has been entered successfully!!!')

    def response_registration(self, connection, mask):
        """
        Function send a response from the server
        for last registration client request
        """
        res_header = struct.pack('<BHI', self.version, self.answer_code, self.response_size)
        self.send(connection, mask, res_header, HEADER_SIZE_RESPONSE)
        # if register success send response with data ( client ID )
        if self.answer_code == REGISTRATION_SUCCESS:
            res_payload = struct.pack(f'<{UUID_SIZE}s', self.current_client_id)
            self.send(connection, mask, res_payload, self.response_size)

    def receive_public_key(self, connection, mask, uh):
        """
        Function gets a client's public key send during registration request process
        Decomposes the public key from the payload
        calculate an encrypted AES key
        Also added the public key and encrypted AES key to the client's database table.
        If no errors occurred, Return the AES key to the client
        """
        public_key = self.receive_payload(connection, mask, uh.PayloadSize)
        Public_key = namedtuple('Payload', ['username', 'public_key'])
        upk = Public_key._make(
            self.parse_payload(public_key, username_size=STRING_USERNAME, public_key_size=PUBLIC_KEY_SIZE))  # 160
        self.logger.debug(f"PUBLIC KEY len {upk.public_key} \n, Key:  {binascii.hexlify(upk.public_key , ' ')}")
        self.cursor.execute("SELECT Name FROM clients WHERE ID=:uuid", {"uuid": uh.ClientID})
        client_name = self.cursor.fetchone()
        # If the user is not registered
        if client_name is None:
            self.logger.error('user not registered,Cannot receive public key')
            self.answer_code = GENERAL_SERVER_ERROR
            self.response_size = EMPTY_PAYLOAD
        else:
            encrypted_aes_key = self.encrypt_aes_key(upk.public_key)
            self.logger.debug(f"Generate an encrypted AES key {binascii.hexlify(encrypted_aes_key, ' ')}")
            try:
                # update the answer_code code accordingly.
                self.cursor.execute("UPDATE clients SET PublicKey=:pk, AES=:aes WHERE ID=:uuid",
                                    {"pk": upk.public_key, "aes": encrypted_aes_key, "uuid": uh.ClientID})
                # Update changes in DB
                self.connection.commit()
                self.logger.info(
                    f"ENCRYPTED AES successfully, public KEY saved {upk.public_key}"
                    f" and AES key {binascii.hexlify(encrypted_aes_key, ' ')} saved in the DB")
            except Exception as err:
                self.logger.error(f'An error happen during update changes in the DB sed general error response {err}')
                self.answer_code = GENERAL_SERVER_ERROR
                self.response_size = EMPTY_PAYLOAD
            self.answer_code = GOT_PUBLIC_KEY_SEND_AES_KEY  # 2102
            self.response_size = UUID_SIZE + len(encrypted_aes_key)
            return encrypted_aes_key

    # AES key response section
    def send_aes_key_response(self, connection, mask, aes_key):
        """
        This function sends a server message
        in case no error happens it's contains an encrypted AES key
        for the client that send a public key
        """
        # send response header anyway
        self.logger.info(f"Send encrypted AES key code {self.answer_code}")
        res_header = struct.pack('<BHI', self.version, self.answer_code, self.response_size)
        self.send(connection, mask, res_header, HEADER_SIZE_RESPONSE)  # 7
        if self.answer_code == GOT_PUBLIC_KEY_SEND_AES_KEY:
            res_payload = struct.pack(f'<{UUID_SIZE}s{len(aes_key)}s',
                                      self.current_client_id, aes_key)
            self.send(connection, mask, res_payload, self.response_size)

    def registration_request_registrant(self, connection, mask, uh):  # 1027
        """
        A re-login request function checks if the client exist in the server DB
        and returns an appropriate answer_code if reconnection
        fails (the client is not registered or does not have a proper public key)
        """
        # Receiving cargo
        payload = self.receive_payload(connection, mask, uh.PayloadSize)
        Payload = namedtuple('Payload', ['username'])
        unpacked_payload = Payload._make(self.parse_payload(payload, username_size=STRING_USERNAME))
        # Search if client exist n the DB
        self.logger.debug(f'Search for an existing customer with Name {unpacked_payload.username} in the DB')
        self.logger.info(
            f'client ID {uh.ClientID}, username {unpacked_payload.username} request code {uh.req_code}')
        name_list = ['Name', 'AES', 'PublicKey']
        self.cursor.execute("""SELECT {} FROM clients WHERE Name=:name""".format(", ".join(name_list)),
                            {"name": unpacked_payload.username})
        # cursor.fetchone function takes the last rows if the user is registered()
        username, aes_key, public_key = self.cursor.fetchone()
        self.logger.debug(f'print user name from the server {username}')
        if (username is not None) & (aes_key != 0) & (public_key != 0):
            # client exist in the DB using exist keys
            self.current_client_id = uh.ClientID
            self.logger.info(f'Client {username} exists with a UUID: {self.current_client_id}'
                             f' send exist AES key to client')
            # 2105 if successful
            self.answer_code = CONFIRMS_RETURN_REQUEST
            self.response_size = UUID_SIZE + len(aes_key)
        else:
            # In case of failure report failure, client should register again as new client 1025
            self.logger.warning(
                f'The client {uh.ClientID} is not registered / there is no proper public key, send to register as new '
                f'user')
            self.answer_code = RELOGIN_REQUEST_FAIL
            self.response_size = UUID_SIZE
            # A new UUID will add when client will send a new registration request
            self.current_client_id = uh.ClientID
        return aes_key

    def login_again_registration_response(self, connection, mask, encrypted_aes_key):
        """
        The reconnection request function sends encrypted AES keys,
        if the client is registered or has a valid public key other send failure response
        """
        # send response header anyway
        self.logger.debug(f'Re-login done response status {self.answer_code} response size {self.response_size}')
        res_header = struct.pack('<BHI', self.version, self.answer_code, self.response_size)
        self.send(connection, mask, res_header, HEADER_SIZE_RESPONSE)  # 7
        if self.answer_code == CONFIRMS_RETURN_REQUEST:
            self.logger.debug(f'sending CONFIRMS_RETURN_REQUEST encrypted aes key len {len(encrypted_aes_key)} ')
            res_payload = struct.pack(f'<{UUID_SIZE}s{len(encrypted_aes_key)}s',
                                      self.current_client_id, encrypted_aes_key)
            self.send(connection, mask, res_payload, self.response_size)
        elif self.answer_code == RELOGIN_REQUEST_FAIL:
            res_payload = struct.pack(f'<{UUID_SIZE}s', self.current_client_id)
            self.send(connection, mask, res_payload, self.response_size)

    def encrypt_aes_key(self, public_key: bytes):
        """
        Function for encrypts an AES key using given public key in RSA
        """
        self.logger.debug(f'AES__KEY = {self.AES_key} type {type(self.AES_key)}')
        self.logger.debug(f'PUBLIC__KEY {public_key} type {type(public_key)}')
        key = RSA.importKey(public_key)
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(self.AES_key)
        return ciphertext

    def receiving_file(self, connection, mask, uh):
        """
        This function handle a request of send file to server
        calculate it's size decode the file, calc CRC for given file
        returns crc and unpacked payload with file
        """
        received_file = self.receive_payload(connection, mask, uh.PayloadSize)
        Receive_file = namedtuple('Receive_file',
                                  ['ContentSize', 'full_file_name', 'message_content'])
        # Calculate file size
        file_size = uh.PayloadSize - CONTENT_SIZE - STRING_FILENAME
        upf = Receive_file._make(
            self.parse_payload(received_file, c_size=CONTENT_SIZE,
                               f_name=STRING_FILENAME, f_size=file_size))
        self.logger.debug(f" The received file size: {file_size} file name {upf.full_file_name}")
        self.logger.debug(f'file content size {binascii.hexlify(upf.ContentSize)}')

        dec_file = self.decrypt_file(upf.message_content)
        if dec_file == 0:
            self.answer_code = GENERAL_SERVER_ERROR
            self.response_size = EMPTY_PAYLOAD
            return
        file_name = FileUtils.extract_file_name(upf.full_file_name)
        self.logger.debug(f"In receive file AES key size : {len(self.AES_key)}")
        self.logger.debug(f"In receive file {file_name} DECRYPTED CONTENT: {dec_file}")
        file_path = self.save_file(dec_file, upf)
        # Call to a function calculates CRC
        check_sum = CheckSum(file_path)
        crc = check_sum.getCheckSumFile()
        # After calculating the calculated CRC returns the UPF and CRC
        self.logger.debug(f"server calculated the CRC {crc}")
        return upf, crc

    ############################################

    def response_received_file(self, connection, mask, upf, crc):
        """
        send response to client after send file
        based on CRC result
        """
        self.logger.debug(f"In response received file response code {self.answer_code}")
        if self.answer_code != GENERAL_SERVER_ERROR:
            self.answer_code = CRC_OK
            self.response_size = CRC_RESPONSE

        res_header = struct.pack('<BHI', self.version, self.answer_code, self.response_size)  # 2103||2102
        self.send(connection, mask, res_header, HEADER_SIZE_RESPONSE)
        if self.answer_code == CRC_OK:
            crc = str(crc).encode()
            self.logger.debug(f'send CRC OK response CRC is {crc} len {len(crc)}')
            self.logger.debug(f" UUID {self.current_client_id} contentSize {upf.ContentSize} file name {upf.full_file_name}")
            res_payload = struct.pack(f'<{UUID_SIZE}s{CONTENT_SIZE}s{STRING_FILENAME}s{CHECKSUM_SIZE}s',
                                      self.current_client_id, upf.ContentSize, upf.full_file_name, crc)  # 16|4|255|4
            self.send(connection, mask, res_payload, self.response_size)  # 16+4+255+4

    def decrypt_file(self, message_content):
        """
        This function get an encrypted message connect
        and returns the decrypted content, in case of error returns zeros
        """

        try:
            cipher = AES.new(self.AES_key, AES.MODE_CBC, IV)
            decrypted = cipher.decrypt(message_content)
            self.logger.debug(f'Decrypt file done , type {type(decrypted)}')
            return decrypted
        except Exception as exp:
            self.logger.error(f'An error happen during decrypt file {exp}')
        return 0

    def save_file(self, dec_file, upf):
        """
        This function save given file in server files folder
        Update the file in files table in the DB
        """

        # Extract file name from full string (255)
        file_name = FileUtils.extract_file_name(upf.full_file_name)
        file_path = FileUtils.save_file(self, file_name, dec_file)
        # Inserting a file into the file table, file didn't verify yet
        self.cursor.execute("INSERT INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)",
                            (self.current_client_id, file_name, file_path, False))
        self.logger.debug(f"File {file_path} add to DB but didn't verify yet")
        # Update changes in DB
        self.connection.commit()
        return file_path

    def get_file_name_payload(self, connection, mask, uh):
        """
        Parse a payload from client contains file name only (used for 1028 and 1029)
        :param connection:
        :param mask:
        :param uh:
        :return: File name
        """
        received_file = self.receive_payload(connection, mask, uh.PayloadSize)
        Receive_file = namedtuple('Receive_file', ['full_file_name'])
        up = Receive_file._make(self.parse_payload(received_file, f_name=STRING_FILENAME))
        self.logger.debug(up.full_file_name)
        return FileUtils.extract_file_name(up.full_file_name)

    def verifies_file(self, connection, mask, uh):
        """
        This function updates the files in the DB
        after it has been successfully received and verify CRC check is ok
        """
        file_name = self.get_file_name_payload(connection, mask, uh)
        self.cursor.execute("UPDATE files SET Verified=:ver WHERE FileName=:f_name",
                            {"ver": True, "f_name": file_name})
        # Update changes in DB
        self.connection.commit()

    def message_confirmation_response(self, connection, mask, uh):
        """
        This function send a message with answer code - 2104
         means Server received a message, thank you.
        (This message can be received as a response to message 1029 or 1031 from the customer.)
        :param connection:
        :param mask:
        :param uh: unpack header
        """
        # Function message confirmation, thank you
        self.answer_code = MESSAGE_CONFIRMATION
        self.response_size = EMPTY_PAYLOAD
        res_head = struct.pack('<BHI', self.version, self.answer_code, self.answer_code)
        self.send(connection, mask, res_head, HEADER_SIZE_RESPONSE)
        self.close_connection_with_client(connection, uh.ClientID)

    def read_bytes(self, connection, mask, uh):
        """
        This function reads the received
        bytes to clear the socket
        """
        self.receive_payload(connection, mask, uh.PayloadSize)

    def delete_file(self, connection, mask, uh):
        """
         A function to delete a file after the
         file has not been verified , CRC is incorrect three times
        """
        payload = self.receive_payload(connection, mask, uh.PayloadSize)
        Payload = namedtuple('received_file', ['ClientID', 'full_file_name'])
        up = Payload._make(self.parse_payload(payload, id_size=UUID_SIZE, f_name=STRING_FILENAME))
        FileUtils.delete_file(self, up.full_file_name)
        # close client connection socket
        self.close_connection_with_client(connection, uh.ClientID)

    @staticmethod
    def receive_header(connection, mask) -> bytes:
        """
        this function returns header in bytes
        """
        header = connection.recv(HEADER_SIZE)
        # If the title is not found brings a message
        if not header:
            raise Exception('Could not process request, missing header')
        if len(header) != HEADER_SIZE:
            raise Exception(f'Invalid header size {len(header)}. size should be {HEADER_SIZE}')
        return header

    @staticmethod
    def unpack_header(header) -> tuple:
        """
        This function unpacks the header (base16)
        header: A request header send from a client
        return header data as tuple
        """
        return struct.unpack('<16sBHI', header)

    @staticmethod
    def receive_payload(connection, mask, size) -> bytes:
        """
        this function receives the client payload from socket.
        connection : connection socket with client
        size: payload size (bytes)
        returns payload (bytes object)
        """
        # receive payload data from socket
        data = connection.recv(size)
        if not data:
            # When a charge is missing brings a message:
            raise Exception(f'Missing payload, request cancelled with size {size}')
        if len(data) != size:
            raise Exception(
                f"Payload too short, number of bytes received ({len(data)}) different than payload size ({size})")
        return data

    @staticmethod
    def parse_payload(payload, **kwargs) -> tuple:
        """
        this function gets the payload bytes object,
        and unpacks it in a way that the resulted bytes
        would split into categories according to key
         word arguments provided.
        payload: payload received from client
        """
        if len(payload) > sum(
                kwargs.values()):
            raise Exception("invalid size, Could not parse payload")
        splitter = ''
        for num_bytes in kwargs.values():
            # create format for unpacking payload
            splitter += f'{num_bytes}s'
        # unpack payload to wanted fields
        return struct.unpack(splitter, payload)

    @staticmethod
    def send(connection, mask, data, amount):
        """
        This function sends a response
        via a socket.
        """
        # send data in bytes through socket
        bytes_sent = connection.send(data)
        if bytes_sent != amount:
            raise Exception(f'Invalid amount of bytes. sent: {bytes_sent} bytes. '
                            f'should be send: {amount} bytes.')

    @staticmethod
    def open_sql_db(self):
        """
        This function opens a sqlite database.
         then creates a clients table and files table with the following
        """

        if not os.path.exists(DEFENSIVE_DB):
            open(DEFENSIVE_DB, 'ab')

        # database file already exist
        connection = sqlite3.connect(DEFENSIVE_DB)
        cursor = connection.cursor()
        # Create table is not exist
        cursor.execute(
            '''CREATE TABLE IF NOT EXISTS clients (ID BLOB, Name BLOB, PublicKey BLOB, LastSeen TEXT, AES BLOB)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS files(ID BLOB, FileName TEXT, PathName TEXT, Verified BLOB)''')
        # changes in DB
        connection.commit()
        self.logger.debug('Created Clients Tables and Files Tables done successfully')
        return connection, cursor

    def close_connection_with_client(self, connection, client_id):
        """
        This function closes the connection with given client , remove it form the clientsdatabase
         call to close closes the selector, the sql db, and the socket
        param conn: client's socket connection to be closed
        ClientID: client ID we want to remove
        """
        username = "Unregistered client"
        if client_id is not None:
            try:
                self.cursor.execute("SELECT Name FROM clients WHERE ID=:uuid",
                                    {"uuid": client_id})
                username = self.cursor.fetchone()
                if username is not None:
                    self.logger.warning(f'Closing connection with client , remove user Name: {username} from DB')
                    self.cursor.execute("DELETE FROM clients WHERE Name =:uuid", {"uuid": client_id})
                    # Update changes in DB
                    self.connection.commit()
                else:
                    self.logger.warning(f'cannot delete clientID {client_id} from DB, user not exists')

            except Exception as err:
                self.logger.warning(f'Close connection with unknown user {err}')
        self.logger.warning(f'Closing a contact with a customer: {username}----\n\n\n')
        # Anyway unregister this client and close connection
        self.sel.unregister(connection)
        connection.close()

    def close(self):
        """
        An API for close connections
        close the selector,
        the socket, and the sql db
        """
        self.sel.close()
        self.sock.close()
        self.connection.close()
