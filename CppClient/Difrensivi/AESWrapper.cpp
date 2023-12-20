#include "AESWrapper.h"
#include <immintrin.h>
#include <modes.h>
#include <aes.h>
#include <files.h>
#include <stdexcept>
#include <filters.h>
#include "iostream"

using namespace std;
//Forward declaration of functions
unsigned char* generate_key(unsigned char* buffer, unsigned int length);
const CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };
//Constructors 
AESWrapper::AESWrapper()
{
	generate_key(_key, DEFAULT_KEY_LENGTH);
}

AESWrapper::AESWrapper(const unsigned char* key, unsigned int length)
{
	if (length != DEFAULT_KEY_LENGTH)
		throw std::length_error("key length must be 16 bytes not: "+length);
	memcpy_s(_key, DEFAULT_KEY_LENGTH, key, length);
}
//Auto destructor
AESWrapper::~AESWrapper()
{
}
//Getter
const unsigned char* AESWrapper::get_key() const
{
	return _key;
}
//Public APIs
std::string AESWrapper::encrypt(const char* plain, const unsigned int length)
{
	CryptoPP::AES::Encryption aesEncryption(_key, DEFAULT_KEY_LENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbc_encryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stf_encryption(cbc_encryption, new CryptoPP::StringSink(cipher), CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING);
	stf_encryption.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
	stf_encryption.MessageEnd();
	cout << "encrypt file done length" << cipher.size() << endl;

	return cipher;
}

std::string AESWrapper::decrypt(const char* cipher, const unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

	CryptoPP::AES::Decryption aes_decryption(_key, DEFAULT_KEY_LENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbc_decryption(aes_decryption, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryption(cbc_decryption, new CryptoPP::StringSink(decrypted));
	stfDecryption.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryption.MessageEnd();

	return decrypted;
}

const std::string AESWrapper::encryptFile(std::filesystem::path path, std::string aesKey)
{
	std::ifstream to_send(path, std::ios::binary);

	unsigned char key_temp[AESWrapper::DEFAULT_KEY_LENGTH];
	memcpy_s(key_temp, sizeof(key_temp), aesKey.c_str(), aesKey.length());

	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;

	e.SetKeyWithIV(key_temp, sizeof(key_temp), iv);

	std::string cipher;
	CryptoPP::FileSource fs(to_send, true, new CryptoPP::StreamTransformationFilter(e, new CryptoPP::StringSink(cipher)));
	return cipher;
}

const size_t AESWrapper::get_encryptedFile_size(const std::filesystem::path& path) {
	return (size_t)(ceil(std::filesystem::file_size(path) / static_cast<int>(CryptoPP::AES::BLOCKSIZE)) + 1) * static_cast<int>(CryptoPP::AES::BLOCKSIZE);
}

//Private APIs
unsigned char* generate_key(unsigned char* buffer, const unsigned int length)
{
	for (size_t i = 0; i < length; i += sizeof(unsigned int))
		_rdrand32_step(reinterpret_cast<unsigned int*>(&buffer[i]));
	return buffer;
}