#pragma once
#include <boost/asio.hpp>
#include <boost/crc.hpp>
#include <iostream>
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Base64Convertor.h"
#include <cstdlib>
#include <array>
#include <deque>
#include <map>
#include <vector>
#include "Utils.h"
using boost::asio::ip::tcp;
using namespace std;

typedef array<char, UUID_SIZE> uuid;
typedef array<char, PUBUBLIC_KEY_SIZE> pubKey;

class Client
{
private:

    /*  tcp ip  */
    boost::asio::ip::address ip_;
    uint16_t port_;

    /*  user information and keys */
    string username_;
    string filepath_;
    string filename_;
    string private_key_;
    string public_key_;
    string base64_private_key_;
    string symmetric_key_;
    uuid clientID_ = { 0 };
	/*  session variables   */
    char buffer_data[CHUNK_SIZE] = { 0 };
    uint16_t status = 0;

    /*  session objects     */
    boost::asio::io_context& io_context_;
    tcp::socket socket_;
    boost::system::error_code err;
    RSAPrivateWrapper* rsapriv_ = nullptr; // RSA private/public key pair engine and decrypt
    RSAPublicWrapper* rsapub_ = nullptr;   // RSA encrypt with public key
    RSAPrivateWrapper* dec_rsapriv_ = nullptr; // RSA decrypt with private key 

    /*Client - server communications private functions*/
    //Parse client details from TRANSFER_INFO file
    void parse_transfer_info_file();
    //Send a request of register a new client
    void send_registration_request();
    //Send a request of re-login existing client
    void send_repeat_registration_request();
    //Send user login request, decide if the client is new on exiting based on ME_INFO file
    ResponseHeader* send_user_login_request_to_server(uint16_t requestCode); 
    //Send Public key to server
    string send_public_key();
    //send an encrypted file to the server
    string send_file_request(string symmetricKey);
    //Get an encrypted AES key from server on relogin request
    string get_encrypted_aes_key(ResponseHeader* resHead);
    //Get a AES key fom server (first login)
    string get_aes_key();
   //File CRC verification (client crc vs. server) done succesfully
    void send_crc_succses();
    //File CRC verification (client crc vs. server) fail, CRC are not equal
    void send_file_crc_failed();
    //File CRC verification (client crc vs. server) fail 4 times , stop process
    void send_file_crc_failed_four_times();
    /*Helper function*/

    //Read client details from ME_INFO file , for check if client exist.
    void load_client_id_details();
    /*Read private key file used on re-login process*/
    static string readPrivateKeyFile();
    /* Build a message header for send to server*/
    static vector<char> build_Header(char* clientId, char version, uint16_t code, uint32_t size);
    /*build send file message payload , send to server */
    vector<char> build_file_payload(char* clientId, uint32_t contentSize, const string& fName, const string& encFile);
    /* build send crc message payload*/
    vector<char> build_crc_message_payload(char* clientID, const string& fName);
    /*  send and receive from socket */
    size_t send_bytes(char* data, size_t amount);
	size_t send_bytes(vector<char> vec, size_t amount);
	size_t send_bytes(string str, size_t amount);
    size_t receive_bytes(size_t amount);
    static void clear_buffer(char* buf, uint32_t size);
    static void parse_response_header(ResponseHeader* rh, char* arr);

public:

    Client() = default;
    explicit Client(boost::asio::io_context& io_context);
    ~Client();
    void process_requests();
    void connect_to_server();
    void close_connection();
    char version = SERVER_VERSION;
};
