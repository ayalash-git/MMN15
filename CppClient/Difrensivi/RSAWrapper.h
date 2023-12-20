#include <osrng.h>
#include <rsa.h>
#include <string>
#include "iostream"
using namespace std;
using namespace CryptoPP;

class RSAPublicWrapper
{
public:
	static const unsigned int KEYSIZE = 160;
	static const unsigned int BITS = 1024;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PublicKey _publicKey;

	RSAPublicWrapper(const RSAPublicWrapper& rsapublic);
	RSAPublicWrapper& operator=(const RSAPublicWrapper& rsapublic);
public:

	RSAPublicWrapper(const char* key, unsigned int length);
	RSAPublicWrapper(const string& key);
	~RSAPublicWrapper();

	string getPublicKey() const;
	char* getPublicKey(char* keyout, unsigned int length) const;

	string encrypt(const string& plain);
	string encrypt(const char* plain, unsigned int length);
};


class RSAPrivateWrapper
{
public:
	static const unsigned int BITS = 1024;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PrivateKey _privateKey;

	RSAPrivateWrapper(const RSAPrivateWrapper& rsaprivate);
	RSAPrivateWrapper& operator=(const RSAPrivateWrapper& rsaprivate);
public:
	RSAPrivateWrapper();
	RSAPrivateWrapper(const char* key, unsigned int length);
	RSAPrivateWrapper(const string& key);
	~RSAPrivateWrapper();

	string getPrivateKey() const;
	char* getPrivateKey(char* keyout, unsigned int length) const;

	string getPublicKey() const;
	char* getPublicKey(char* keyout, unsigned int length) const;

	string decrypt(const string& cipher);
	string decrypt(const char* cipher, unsigned int length);
};

#pragma once
