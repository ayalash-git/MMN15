#include <stdio.h>
#include <iostream>
#include <utility>
#include <vector>
#include "Client.h"
#include "Utils.h"
#include <algorithm>
#include <fstream>
#include <array>
#include <filesystem>
#include <iomanip>
#include <boost/crc.hpp>
#include <boost/asio.hpp>
#include "CheckSum.h"
#include "ConvertorUtils.h"
#include "FileUtils.h"

using namespace std;
using boost::asio::ip::tcp;


//The builder reads the transfer details and obtains his information about the customer.
Client::Client(boost::asio::io_context& io_context) : io_context_(io_context), socket_(io_context)
{
	parse_transfer_info_file();

}

//default destructor
Client::~Client(void)
{

}

/*
* This Function reads the transfer information from the "transfer.info" file.
* The information contains the server's IP and port, the client's username and the path
   to the file that will be sent to the server.
* The function checks if all the information is valid and assigns to the class members.
* This function reads the transfer information from the "transfer.info" file.
*/
//A function receives the file transfer.info with parameters line, port, IP, file path
void Client::parse_transfer_info_file()
{
	string line;
	string port;
	string ip;
	string filepath;
	size_t pos = 0;

	//opens the file transfer.info , throw exception if not exist
	ifstream file = FileUtils::open_input_file(TRANSFER_INFO_FILE);

	//read ip and port from file
	getline(file, line);

	//If a file transfer.info is empty close the file
	if (line.empty())
	{
		file.close();
		string err =  "'transfer.info' file contains invalid number of lines " +to_string(line.size());
		throw exception(err.c_str());
	}

	pos = line.find(':');
	if (pos != string::npos)
	{
		ip = line.substr(0, pos);
		port = line.substr(pos + 1);
	}
	else {
		file.close();
		string err = "Invalid port info format" + line;
		throw exception(err.c_str());
	}

	// Check if the IP and port are correct
	if (!port.empty() && port.size() <= 4)
		port_ = stoi(port);
	else
	{
		file.close();
		throw exception("The port number is incorrect");
	}

	boost::asio::ip::address ip_add = boost::asio::ip::make_address(ip);

	if (!ip_add.is_v4())
	{
		file.close();
		throw exception("The given ip address number is incorrect");
	}
	// assign to class member
	ip_ = ip_add;
	//get user name line
	getline(file, line);
	if (line.empty() || line.size() > MAX_USERNAME)
	{
		file.close();
		throw exception("username is not valid in file 'transfer.info' ");
	}
	//assign to class member
	username_ = line;
	//get file path
	getline(file, line);
	if (line.empty() || line.size() > MAX_FILENAME)
	{
		file.close();
		string err = "file path "+ line+" length " + to_string(line.size())  + " not valid in file 'tansfer.info' ";
		throw exception(err.c_str());
	}
	ifstream file_Path;
	file_Path.open(line);
	//If the file path send to the server is not found
	if (!file_Path)
	{
		file.close();
		throw exception("file path does not exist");
	}
	filepath_ = line;
	std::string base_filename = line.substr(line.find_last_of("/\\") + 1);
	filename_ = base_filename;

	//printing ip and port ,username,filename,path
	cout << "IP:  " << ip << " Port:  " << port << " User Name:  "
		<< username_ << " File Name:  " << filename_ << endl << " Full File Path:  " << filepath_ << endl;

	//Closing a file ending processing it
	file.close();
}


//This function handles the processing of client requests from the server
void Client::process_requests()
{
	string dec_file;
	try{

		cout << "-----> Start process a request" << endl;
		//First request send , connect to server
		connect_to_server();
		//check if me.info does not exist, which means the user does not registered
		const std::filesystem::path cwd = std::filesystem::current_path() / ME_INFO_FILE;
		if (std::filesystem::exists(cwd.string()))
		{
			cout << "--> User already exist me.info file exist send repeat login request!"<< endl;
			//load CLIENT ID data from ME_INFO file
			load_client_id_details();
			//load private key data from priv.key file
			private_key_ = readPrivateKeyFile();

			send_repeat_registration_request();

		}
		else
		{
			cout << "send registration request" << endl;
			
			send_registration_request();

		}
		uint8_t send_times = 0;
		CheckSum checksum;
		do{
				//Verify the file up to 3 times
				cout << "Send file to server " << send_times + 1 << " times " << endl;

				const string client_CRC = checksum.getFileCheckSum(filepath_);
				const string server_CRC = send_file_request(symmetric_key_);
				cout << "client_CRC " << client_CRC << endl;
				cout << "server_CRC " << server_CRC << endl;
				if (server_CRC != client_CRC)
				{
					send_file_crc_failed();
					send_times++;
					cout << "Client CRC is different than server CRC time: " << send_times << endl;
				}
				else
				{
					cout << "CRC are equals!!!!!!!" << endl;
					//If he was able to compare it
					send_crc_succses();
					break;
				}
			
		} while (send_times<= SEND_TIMES);
		

		if (send_times> SEND_TIMES)
		{
			cout << "CRC failed four times " << endl;
			//CRC verifcation failed 4 time , send final bad message to server
			send_file_crc_failed_four_times();
		}
		
	}
	catch (exception& e)
	{
		cerr << "Exception: " << e.what() << "\n";
	}
}


ResponseHeader* Client::send_user_login_request_to_server(uint16_t requestCode) {

	if(std::strcmp(clientID_.data(), "0x0") == 0x0)
	{
		throw new InvalidArgument("send_user_login_request_to_server got invalid client ID");
	}
	const vector<char>header = build_Header(clientID_.data(), version, requestCode, MAX_USERNAME);//1025 or 1027
	cout << "******* Send request header to send_user_login_request_to_server ID: " << clientID_.data() << " request code : " << requestCode << endl;
	send_bytes(header, HEADER_SIZE); //send request header 23
	std::vector<char> userNameData(MAX_USERNAME);
	std::copy(username_.begin(), username_.end() , userNameData.begin());
	cout << "Send payload data - user name " << userNameData.data() << " size : " << userNameData.size() << endl;
	send_bytes(userNameData.data(), MAX_USERNAME); //Send user name data size is 255

	receive_bytes(HEADER_SIZE_RESPONSE);

	auto* resHead = new ResponseHeader;
	parse_response_header(resHead, buffer_data);
	return resHead;
}


string Client::get_encrypted_aes_key(ResponseHeader* resHead) {

	RSAPrivateWrapper rsapriv;
	string pubkey = public_key_;
	private_key_ = readPrivateKeyFile();
	string base64key2 = private_key_;

	RSAPrivateWrapper rsapriv_other(Base64Convertor::decodeStr(base64key2));
	// receive payload
	size_t aes_key_size = (resHead->payloadSize) - UUID_SIZE;
	cout << "Got AES key size" << aes_key_size << endl;
	//get UUID 
	receive_bytes(UUID_SIZE);
	// AES key length
	receive_bytes(aes_key_size);

	cout << "encrypted AES :" << endl;
	ConvertorUtils::charToHex((unsigned char*)buffer_data, sizeof(buffer_data));

	string cipher = ConvertorUtils::convert_to_string(buffer_data);
	cout << "cipher len = " << cipher.length() << endl;
	string decrypted = rsapriv_other.decrypt(cipher);
	cout << "decrypted AES:" << endl;

	ConvertorUtils::charToHex((unsigned char*)decrypted.c_str(), decrypted.length());
	delete(resHead);
	return decrypted;
}
/*
This function for a registration request if a user exists informs
status 2101 if not existing save it's details to ME info file
 */
void Client::send_registration_request()
{
	auto* resHead = new ResponseHeader;
	resHead = Client::send_user_login_request_to_server(REGISTER_REQUEST);


	if (resHead->statusCode == REGISTER_FAILED)//2101
	{
		delete(resHead);
		throw exception("send_registration_request - Regeneration failed, User already exists");
	}
	if (resHead->statusCode != REGISTER_SUCCESS)//invalid server response
	{
		delete(resHead);
		const string error_message = "send_registration_request - regeneration request , got invalid server status code." + resHead->statusCode;
		throw exception(error_message.c_str());
	}
	if (resHead->payloadSize != UUID_SIZE)
	{
		delete(resHead);
		throw exception("send_registration_request got invalid payload size :" + resHead->payloadSize);
	}

	cout << "Server status code: " << resHead->statusCode << endl;

	// receive payload
	receive_bytes(UUID_SIZE);
	memcpy(clientID_.data(), buffer_data, UUID_SIZE);
	cout << "Creating client's file : " << ME_INFO_FILE << " user name : " << username_ << endl;
	cout << "UUID: " << ConvertorUtils::hex2Ascii(clientID_.data(), UUID_SIZE) << "PRIVATE_KEY_FILE_ " << private_key_ << endl;
	delete(resHead);
	//register new client , save its details in me.info file
	//open file , exit with error in inner function
	ofstream me_file = FileUtils::open_out_file(ME_INFO_FILE);
	//line 1 user name
	me_file << username_ << endl;
	//line 2 Client UUID in ASCII format
	me_file << ConvertorUtils::hex2Ascii(clientID_.data(), UUID_SIZE) << endl;
	//line 3 private key 
	me_file << private_key_ << std::endl;
	//close file
	me_file.close();

	//Send a public key to the server and get an AES key encrypted with the public key we sent
	symmetric_key_ = send_public_key();
}

//send a repeat registration request
void Client::send_repeat_registration_request()
{
	auto* resHead = new ResponseHeader;
	resHead = Client::send_user_login_request_to_server(RELOGIN_REQUEST);

	if (resHead->statusCode == REJECT_RELOGIN_REQUEST)
	{
		cout << "Repeat Regeneration failed, User didn't exists, please register. Or, Public Key is not valid." << endl;

		//If the payload size is invalid
		if (resHead->payloadSize != UUID_SIZE)
		{
			delete(resHead);
			const string error = "for request REJECT_RELOGIN_REQUEST (2106) got invalid payload size." + resHead->payloadSize;
			throw exception(error.c_str());
		}
		else {

			//register new client , save its details in me.info file
			cout << "re login fail register again as new user " << endl;
			try {
				send_registration_request();
			}
			catch (Exception) {
				cerr << "an unexpected error happenes during re-login process , please send new request"  << endl;
			}
			
		}
	}
	else if (resHead->statusCode != CONFIRM_RELOGIN_REQUEST)
	{
		delete(resHead);
		const string error_message = "Repeat Regeneration , got invalid server status code."+ resHead->statusCode;
		throw exception(error_message.c_str());
	}
	else
	{
		cout << "Repeat registration request success got back an encrypted AES key from server. " <<endl;
		//get AES key from server
		symmetric_key_ = get_encrypted_aes_key(resHead);
		cout << "symmetric key " << symmetric_key_ << endl;
		cout << " re-login success , going to send file to server";
	}
}

/*
* This function sends the client's public key to the server,
and receives an AES key encoded by the public key.
*The request includes a header and a payload consisting of the customer's username and public key
*/
//Sending a public key 1026
string Client::send_public_key()
{
	array<char, SYMMETRIC_KEY_SIZE> symetricKey;
	RSAPrivateWrapper rsapriv;
	//get the public key
	string pubkey = rsapriv.getPublicKey();
	//get the private key and encodeStr it as base64 
	private_key_ = Base64Convertor::encodeStr(rsapriv.getPrivateKey());//get the private key and encode it as base64 
	public_key_ = pubkey;
	ofstream privkey_file = FileUtils::open_out_file(PRIVATE_KEY_FILE);
	cout << "Creating private key: " << PRIVATE_KEY_FILE << endl;
	// private key created in the first run of the program in base 64 format
	privkey_file << private_key_ << endl;
	privkey_file.close();

	vector<char>header = build_Header(clientID_.data(), version, SEND_PUBLIC_KEY, MAX_USERNAME + PUBUBLIC_KEY_SIZE);
	// convert string username to bytes vector
	std::vector<char> userNameData(MAX_USERNAME);
	std::copy(username_.begin(), username_.end(), userNameData.begin());
	// sending message
	send_bytes(header, HEADER_SIZE); // Header
	send_bytes(userNameData.data(), MAX_USERNAME);//user name - 255 bytes
	send_bytes(pubkey, PUBUBLIC_KEY_SIZE);//public key 160 bytes
	cout << "public key:" << endl;
	ConvertorUtils::charToHex((unsigned char*)pubkey.c_str(), pubkey.length());
	cout << "Public key size: " << pubkey.length() << endl;

	return get_aes_key();
}


string Client::get_aes_key()
{
	string decrypted;
	receive_bytes(HEADER_SIZE_RESPONSE);
	auto* res_head = new ResponseHeader;
	parse_response_header(res_head, buffer_data);
	cout << "Get AES key response from server " << res_head->statusCode << endl;
	//Sends AES key if not matched RECEIVE_AES_KEY 2102 
	if (res_head->statusCode == RECEIVE_AES_KEY)//if not 2102 either 2105
	{
		cout << "Got an expected encrypted AES key response status" << res_head->statusCode << endl;
		string decrypted = get_encrypted_aes_key(res_head);
		cout << "decrypted AES key:" << decrypted << endl;
	}
	else
	{
		delete(res_head);
		const string error_msg = "Get AES key response , got invalid status code ";
		throw exception(error_msg.c_str());
	}
	return decrypted;
}


string Client::send_file_request(string symetricKey)
{
	cout << "in send_file_request function: " << endl;
	string encrypted_file;
	
	// create encryption engine
	AESWrapper aes((unsigned char*)symetricKey.data(), SYMMETRIC_KEY_SIZE);
	string content = FileUtils::get_file_content(filename_);
	//encrypted_file contains  - encrypted content file
	encrypted_file = aes.encrypt(content.c_str(), content.length());
	
	//std::string encrypted_file= AESWrapper::encryptFile(filepath_, std::move(symetricKey));
	size_t encFile_size = AESWrapper::get_encryptedFile_size(filepath_);
	cout << "Encrypted_file size for send: "<< encFile_size << endl;
	ConvertorUtils::charToHex(reinterpret_cast<const unsigned char*>(encrypted_file.c_str()), encrypted_file.length());	
	
	// send request header and message payload
	const vector<char>header = build_Header(clientID_.data(), version, SEND_FILE, CONTENT_SIZE + MAX_FILENAME + encFile_size);//*& 1028
	const vector<char> payload = build_file_payload(clientID_.data(), encFile_size, filepath_, encrypted_file);

	send_bytes(header, HEADER_SIZE);
	cout << "send file message size: "<<  payload.size() << endl;
	send_bytes(payload, payload.size());

	receive_bytes(HEADER_SIZE_RESPONSE);

	auto* res_head = new ResponseHeader;

	parse_response_header(res_head, buffer_data);

	cout << "After send file server status code: " << res_head->statusCode << endl;

	if (res_head->statusCode != RECEIVE_CRC_OK)
	{
		delete(res_head);
		throw exception("send_file_request got invalid status code" + res_head->statusCode);
	}

	//Total response size is 16 - UUID size | 4 content size | 255 file name | 4 CRC size
	//recieve payload
	receive_bytes(UUID_SIZE + CONTENT_SIZE + MAX_FILENAME);//not needed data
	receive_bytes(CRC_SIZE);//recieve server crc calculation
	ConvertorUtils::charToHex((unsigned char*)buffer_data, sizeof(buffer_data));

	string server_crc = ConvertorUtils::convert_to_string(buffer_data);

	cout << "server crc: " << server_crc << endl;
	delete(res_head);
	return server_crc;
}


void Client::load_client_id_details()
{
	string line;

	//Trying to open me.info file and read the client ID , if file not exist inner function throw exception
	ifstream file = FileUtils::open_input_file(ME_INFO_FILE);
	getline(file, line);
	cout << line << endl; 
	if (line.empty()) {
		
		throw exception("In function load_client_id_details, Couldn't user name");
	}
	//first line should be user name verify it
	if (line == username_)
	{
		//read client ID 
		getline(file, line);
		if (line.empty()) {

			throw exception("In function load_client_id_details, Couldn't get client ID");
		}
		file.close();
	}
	else
	{
		throw exception("In function load_client_id_details, got invalid user name" );
	}
		

	ConvertorUtils::ascii2HexBytes(clientID_.data(), line, UUID_SIZE);
	cout << "Re login - load_client_id_details API Client ID: " << clientID_.data() << " size : " <<clientID_.size() << endl;
	ConvertorUtils::charToHex(reinterpret_cast<const unsigned char*>(clientID_.data()), clientID_.size());
}

string Client::readPrivateKeyFile()
{
	ifstream file = FileUtils::open_input_file(PRIVATE_KEY_FILE);
	string line;
	string file_lines = "";

	do {
		getline(file, line);

		if (!line.empty())
		{
			file_lines += line;
		}
		else
		{
			break;
		}

	} while (true);
	file.close();

	if (file_lines.empty()) {
		throw exception("In function load_private_key_details, Couldn't get private key");
	}

	return file_lines;

}

//this function handles the processes when the CRC of client and server are equal 1029
void Client::send_crc_succses()
{
	/* construct request header and send */
	const vector<char>header = build_Header(clientID_.data(), version, FILE_CRC_OK, MAX_FILENAME);
	const vector<char>crcPayload = build_crc_message_payload(clientID_.data(), filepath_);

	// send header and payload to server
	send_bytes(header, HEADER_SIZE);
	send_bytes(crcPayload, MAX_FILENAME);
	cout << "crcPayload size: " << crcPayload.size() << endl;
	// receive header
	receive_bytes(HEADER_SIZE_RESPONSE);
	auto* resHead = new ResponseHeader;
	parse_response_header(resHead, buffer_data);

	if (resHead->statusCode != GOT_MESSAGE_SUCCESSFULLY) {
		delete(resHead);
		throw exception("CRC_OK message got invalid status code"+ resHead->statusCode);
	}
	else if (resHead->payloadSize != UUID_SIZE){
		delete(resHead);
		throw exception("CRC_OK message got invalid payload size" + resHead->payloadSize);
	}
	else
	{   
		cout << "File " << filename_ << " has been sent successfully!" << endl;
		cout << "---CLOSETING CONNECTION!!---" << endl;
		close_connection();
	}
	//successfully
	cout << "Server status code: " << resHead->statusCode << endl;
	cout << "File " << filename_ << " was successfully received by server" << endl;
}


//Sed CRC fail message with file name in the payload (code 1030)
void Client::send_file_crc_failed()
{
	//construct request header and send 
	const vector<char>header = build_Header(clientID_.data(), version, FILE_CRC_FAILED, MAX_FILENAME);
	send_bytes(header, HEADER_SIZE);
	vector<char>crcPayload = build_crc_message_payload(clientID_.data(), filepath_);
	send_bytes(crcPayload, MAX_FILENAME);
}


//This function when the client and server compare 3 times and failed 4 times closes the server
void Client::send_file_crc_failed_four_times()
{
	const vector<char>header = build_Header(clientID_.data(), version, FILE_CRC_FAILED_FOUR_TIMES, MAX_FILENAME);// UUID_SIZE +
	const vector<char>payload = build_crc_message_payload(clientID_.data(), filepath_);

	send_bytes(header, HEADER_SIZE);
	send_bytes(payload, MAX_FILENAME);

	cout << "Sending the file to the server failed!" << endl;
	cout << "---CLOSE CONNECTION!!---" << endl;
	close_connection();
}

/*
* This function returns a message payload vector according to the given parameters
* and according to protocol.
* Notice that we do not refer to the actual content.
*/
vector<char> Client::build_crc_message_payload(char* clientID, const string& fName)
{
	vector<char> crc_payload;

	const size_t size = fName.length();
	vector<char> fileName(fName.c_str(), fName.c_str() + MAX_FILENAME);
	const vector<char>::iterator iterator= fileName.end();
	fileName.insert(iterator, MAX_FILENAME - size, NULL);

	for (size_t i = 0; i < MAX_FILENAME; i++)
		crc_payload.push_back(static_cast<uint8_t>(fileName[i]));

	cout << "crcPayload size for send: " << crc_payload.size() << endl;
	return crc_payload;
}

/*
* this function builds and returns the client header vector according to the
given parameters and protocol.
*/
vector<char>Client::build_Header(char* clientId, char version_, uint16_t code, uint32_t size)
{
	vector<char> header;
	size_t header_size = 0;
	cout << "" << endl;
	for (size_t i = 0; i < UUID_SIZE; i++)
	{
		header.push_back(static_cast<uint8_t>(clientId[i]));
		header_size += sizeof static_cast<uint8_t>(clientId[i]);
	}
	header.push_back(version_);
	header_size += sizeof(version_);

	header.push_back(static_cast<uint8_t>(code));
	header.push_back(static_cast<uint8_t>(code >> 8));
	header_size += sizeof(static_cast<uint8_t>(code));
	header_size += sizeof(static_cast<uint8_t>(code));
	header.push_back(static_cast<uint8_t>(size));
	header.push_back(static_cast<uint8_t>(size >> 8));
	header.push_back(static_cast<uint8_t>(size >> 16));
	header.push_back(static_cast<uint8_t>(size >> 24));

	header_size += sizeof(static_cast<uint8_t>(size));
	header_size += sizeof(static_cast<uint8_t>(size));
	header_size += sizeof(static_cast<uint8_t>(size));
	header_size += sizeof(static_cast<uint8_t>(size));

	cout << "header_size for send : " << header_size << endl;
	return header;
}


/*
* this function builds and returns the file payload vector
according to the given parameters and protocol.
*/
vector<char> Client::build_file_payload(char* clientId, uint32_t contentSize, const string& fName, const string& encFile)
{
	vector<char> filePayload;

	//insert content size into payload
	filePayload.push_back(static_cast<uint8_t>(contentSize));
	filePayload.push_back(static_cast<uint8_t>(contentSize >> 8));
	filePayload.push_back(static_cast<uint8_t>(contentSize >> 16));
	filePayload.push_back(static_cast<uint8_t>(contentSize >> 24));
	
	
	// convert string file name to bytes vector with max file name size
	vector<char> fileName(fName.c_str(), fName.c_str() + MAX_FILENAME);
	
	for (size_t i = 0; i < MAX_FILENAME; i++)
		filePayload.push_back(static_cast<uint8_t>(fileName[i]));
	cout << " Full size with file size " << filePayload.size();
	const vector<char> enc_file(encFile.c_str(), encFile.c_str() + contentSize);

	for (size_t i = 0; i < contentSize; i++)
		filePayload.push_back(static_cast<uint8_t>(enc_file[i]));

	cout << " Final filePayload size = " << filePayload.size() << endl;
	return filePayload;
}

//This function sends the data to the server through the socket
size_t Client::send_bytes(char* data, size_t amount)
{
	const size_t bytesSent = boost::asio::write(socket_, boost::asio::buffer(data, amount));

	if (bytesSent < amount) {
		const string err = "Sent fewer bytes than expected " + to_string(bytesSent) + " out of " + to_string(amount);
		throw exception(err.c_str());
	}
	//Returns the mission number
	return bytesSent;
}

//This function sends the data to the server through the socket
size_t Client::send_bytes(vector<char> vec, size_t amount)
{
	const size_t bytesSent = boost::asio::write(socket_, boost::asio::buffer(vec, amount));
	
	if (bytesSent < amount) {
		const string err = "Sent fewer bytes than expected " + to_string(bytesSent) + " out of " + to_string(amount);
		throw exception(err.c_str());
	}
	//Returns the mission number
	return bytesSent;
}

//this function sends the data to server through the socket
size_t Client::send_bytes(string str, size_t amount)
{
	const size_t bytes_sent = boost::asio::write(socket_, boost::asio::buffer(str, amount));

	if (bytes_sent < amount) {
		const string err = "Sent fewer bytes than expected " + to_string(bytes_sent)
			+ " out of " + to_string(amount);
		throw exception(err.c_str());
	}
	//number of bytes to send
	return bytes_sent;
}

//Recevie bytes from server trsaction
size_t Client::receive_bytes(size_t amount)
{
	clear_buffer(buffer_data, CHUNK_SIZE);

	const size_t bytesRev = boost::asio::read(socket_, boost::asio::buffer(buffer_data, amount));

	if (bytesRev != amount)
	{
		clear_buffer(buffer_data, CHUNK_SIZE);
		const string err = "Received different bytes than expected " + to_string(bytesRev) + " out of " + to_string(amount);
		throw exception(err.c_str());
	}
	return bytesRev;
}

//this function clears the buffer, in order to prevent receiving/sending old data
void Client::clear_buffer(char* buf, uint32_t size)
{
	for (uint32_t i = 0; i < size; ++i)
		buf[i] = 0;
}

/*
* This function will break down the header data
* The function receives bytes of the response header from the server and saves the form header
* Parameters to their respective fields in the ResponseHeader structure
*/
void Client::parse_response_header(ResponseHeader* rh, char* arr)
{
	rh->serverVersion = static_cast<uint8_t>(arr[0]);

	rh->statusCode = static_cast<uint8_t>(arr[2]) << 8 | static_cast<uint8_t>(arr[1]);

	rh->payloadSize = static_cast<uint8_t>(arr[6]) << 24 |
		static_cast<uint8_t>(arr[5]) << 16 |
		static_cast<uint8_t>(arr[4]) << 8 |
		static_cast<uint8_t>(arr[3]);
	cout << "parse header: ";
	cout << "statusCode " << rh->statusCode << " payload size " << rh->payloadSize << endl;
}

//The function create the connection to server 
void Client::connect_to_server()
{
	socket_.connect(tcp::endpoint(ip_, port_));
	cout << "client connected to server at port:  " << port_ << endl;
}

//The function close the connection to server 
void Client::close_connection()
{
	socket_.close();
	cout << "client close connected to server at port:  " << port_ << endl;

}
