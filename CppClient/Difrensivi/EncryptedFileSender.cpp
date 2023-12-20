#include "EncryptedFile.h"
#include <fstream>

#include <modes.h>
#include <aes.h>
#include <filters.h>
#include <files.h>
#include <asio/ip/tcp.hpp>

#include "AESWrapper.h"

const CryptoPP::byte EncryptedFile::iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

EncryptedFile::EncryptedFile(std::filesystem::path path, std::string key) : file_path(path), _aes_key(key) {}

#define CHUNK_SIZE (1024)

std::string EncryptedFile::send() {
	std::ifstream to_send(file_path, std::ios::binary);

	unsigned char key_temp[AESWrapper::DEFAULT_KEY_LENGTH];
	memcpy_s(key_temp, sizeof(key_temp), _aes_key.c_str(), _aes_key.length());

	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;

	e.SetKeyWithIV(key_temp, sizeof(key_temp), iv);

	std::string cipher;
	CryptoPP::FileSource fs(to_send, true, new CryptoPP::StreamTransformationFilter(e, new CryptoPP::StringSink(cipher)));
	return cipher;
}

size_t EncryptedFile::encrypted_size() {
	return (size_t)(ceil(std::filesystem::file_size(file_path) / static_cast<int>(CryptoPP::AES::BLOCKSIZE)) + 1) * static_cast<int>(CryptoPP::AES::BLOCKSIZE);
}