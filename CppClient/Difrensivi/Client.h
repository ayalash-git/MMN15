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
    void parse_transfer_info_file();
    void send_registration_request();
    void send_repeat_registration_request();
    ResponseHeader* send_user_login_request_to_server(uint16_t requestCode);
    string get_encrypted_aes_key(ResponseHeader* resHead);
    string send_public_key();
    string getAES_key();
    string send_file_request(string symmetricKey);
    void CRC_succses();
    void CRC_failed();
    void CRC_failed_four_times();
    void load_client_id_details();
    string load_private_key_details();
    static string readPrivateKeyFile();
    string get_file_content(string filename);
    static ofstream open_out_file(const string& filename);
    static ifstream open_input_files(const string& filename);
    static vector<char> build_Header(char* clientId, char version, uint16_t code, uint32_t size);
    vector<char> build_file_payload(char* clientId, uint32_t contentSize, const string& fName, const string& encFile);
    vector<char> build_CRC_payload(char* clientID, const string& fName);
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
