#pragma once

#include <filesystem>
#include <string>
using namespace std;

class AESWrapper
{
public:
	static constexpr unsigned int DEFAULT_KEY_LENGTH = 16;//length
private:
	unsigned char _key[DEFAULT_KEY_LENGTH];
	AESWrapper(const AESWrapper& aes);
public:
	//Constructor
	AESWrapper();
	AESWrapper(const unsigned char* key, unsigned int size);
	~AESWrapper();//Descerctor
	//Public APIs
	const unsigned char* get_key() const;

	string encrypt(const char* plain, unsigned int length);
	string decrypt(const char* cipher, unsigned int length);
	/// <summary>
	/// Encrypts and sends a file through the socket.
	/// </summary>
	static const std::string encryptFile(std::filesystem::path path, std::string key);
	static const size_t get_encryptedFile_size(const std::filesystem::path& path);
};
