#include "Base64Convertor.h"
#include <filters.h>
#include <string>
#include <base64.h>//cryptopp890/
//using namespace CryptoPP;


using namespace std;

string Base64Convertor::encodeStr(const string& str)
{
	string encoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded)
		)
	);

	return encoded;
}

string Base64Convertor::decodeStr(const string& str)
{
	std::string decoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded)
		)
	);

	return decoded;
}