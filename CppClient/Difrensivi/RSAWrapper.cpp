#include "RSAWrapper.h"


RSAPublicWrapper::RSAPublicWrapper(const char* key, unsigned int length)
{
	CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(key), length, true);
	_publicKey.Load(ss);
}

RSAPublicWrapper::RSAPublicWrapper(const string& key)
{
	CryptoPP::StringSource ss(key, true);
	_publicKey.Load(ss);
}

RSAPublicWrapper::~RSAPublicWrapper()
{
}

string RSAPublicWrapper::getPublicKey() const
{
	string key;
	CryptoPP::StringSink ss(key);
	_publicKey.Save(ss);
	return key;
}

char* RSAPublicWrapper::getPublicKey(char* keyout, unsigned int length) const
{
	CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte*>(keyout), length);
	_publicKey.Save(as);
	return keyout;
}

string RSAPublicWrapper::encrypt(const string& plain)
{
	string cipher;
	const CryptoPP::RSAES_OAEP_SHA_Encryptor e(_publicKey);
	CryptoPP::StringSource ss(plain, true, new CryptoPP::PK_EncryptorFilter(_rng, e, new CryptoPP::StringSink(cipher)));
	return cipher;
}

string RSAPublicWrapper::encrypt(const char* plain, unsigned int length)
{
	string cipher;
	const CryptoPP::RSAES_OAEP_SHA_Encryptor e(_publicKey);
	CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(plain), length, true, new CryptoPP::PK_EncryptorFilter(_rng, e, new CryptoPP::StringSink(cipher)));
	return cipher;
}


//Default constructor
RSAPrivateWrapper::RSAPrivateWrapper()
{
	_privateKey.Initialize(_rng, BITS);
}

RSAPrivateWrapper::RSAPrivateWrapper(const char* key, unsigned int length)
{
	CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(key), length, true);
	_privateKey.Load(ss);
}

RSAPrivateWrapper::RSAPrivateWrapper(const string& key)
{
	CryptoPP::StringSource ss(key, true);
	_privateKey.Load(ss);
}

RSAPrivateWrapper::~RSAPrivateWrapper()
{
}

string RSAPrivateWrapper::getPrivateKey() const
{
	string key;
	CryptoPP::StringSink ss(key);
	_privateKey.Save(ss);
	return key;
}

char* RSAPrivateWrapper::getPrivateKey(char* keyout, unsigned int length) const
{
	CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte*>(keyout), length);
	_privateKey.Save(as);
	return keyout;
}

string RSAPrivateWrapper::getPublicKey() const
{
	const CryptoPP::RSAFunction publicKey(_privateKey);
	string key;
	CryptoPP::StringSink ss(key);
	publicKey.Save(ss);
	return key;
}

char* RSAPrivateWrapper::getPublicKey(char* keyout, unsigned int length) const
{
	const CryptoPP::RSAFunction publicKey(_privateKey);
	CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte*>(keyout), length);
	publicKey.Save(as);
	return keyout;
}

string RSAPrivateWrapper::decrypt(const string& cipher)
{
	string decrypted;
	cout << "RSA wrapper decrypt " << endl;
	const CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
	CryptoPP::StringSource ss_cipher(cipher, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
	cout << decrypted << endl;
	return decrypted;
}

string RSAPrivateWrapper::decrypt(const char* cipher, unsigned int length)
{
	string decrypted;
	const CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
	CryptoPP::StringSource ss_cipher(reinterpret_cast<const CryptoPP::byte*>(cipher), length, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
	return decrypted;
}
