#pragma once
#include <aes.h>
#include <filesystem>
#include <boost/asio.hpp>
#include <aes.h>

/// <summary>
/// This class helps with sending encrypted files and operating on them.
/// </summary>
class EncryptedFile
{
	/// <summary>
	/// Holds the current AES Key.
	/// </summary>
	std::string _aes_key;
	/// <summary>
	/// AES Encryption provider reference.
	/// </summary>
	CryptoPP::AES::Encryption _aes_encryption;
	/// <summary>
	/// Holds the IV for the AES encryption
	/// </summary>
	static const CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];

	/// <summary>
	/// holds the current file path
	/// </summary>
	std::filesystem::path file_path;

public:
	/// <summary>
	/// Creates a new encrypted file sender.
	/// <param name="file_path">The source file path.</param>
	/// </summary>
	EncryptedFile(std::filesystem::path file_path, std::string aes_key);

	/// <summary>
	/// Encrypts and sends a file through the socket.
	/// </summary>
	std::string send();

	/// <summary>
	/// Returns the file size, after it was encrypted.
	/// </summary>
	size_t encrypted_size();
};