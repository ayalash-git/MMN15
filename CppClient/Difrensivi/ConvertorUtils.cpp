#include "ConvertorUtils.h"
#include <stdio.h>
#include <iostream>
#include <utility>
#include <vector>
#include <fstream>
#include <array>
#include <filesystem>
#include <iomanip>
#include <boost/crc.hpp>
#include <boost/asio.hpp>

using namespace std;
using boost::asio::ip::tcp;

ConvertorUtils::~ConvertorUtils()
{
}

////Public APIS

/*
* An API for convert ASCII data to string
*/
void ConvertorUtils::ascii2String(string* dest, const string& src, unsigned int len)
{
	string bytes;
	stringstream converter;
	converter << hex << setfill('0');

	for (size_t i = 0; i < (2 * len); i += 2)
	{
		converter << hex << src.substr(i, 2);
		int byte;
		converter >> byte;
		bytes += byte & 0xFF;
		converter.str(string());
		converter.clear();
	}
	memcpy_s(dest, len, bytes.c_str(), len);
}

//The function convert array to string 
/*
* An PAI for convert Array to string
*/
string ConvertorUtils::convert_to_string(const char* buffer)
{
	string str;
	for (size_t i = 0; i < 128; i++) {
		str += buffer[i];
	}
	return str;
}

//this function converts from hexadecimal to Ascii
string ConvertorUtils::hex2Ascii(const char* arr, size_t len)
{
	stringstream converter;
	converter << hex << setfill('0');

	for (size_t i = 0; i < len; i++)
		converter << setw(2) << (static_cast<unsigned>(arr[i]) & 0xFF);
	return converter.str();
}
/*
* A API for convert a string in ASCII format to hex bytes
*/
void ConvertorUtils::ascii2HexBytes(char* dest, const string& src, size_t len)
{

	string bytes;
	stringstream converter{};
	converter << hex << setfill('0');

	for (size_t i = 0; i < (len * 2); i += 2)
	{
		converter << hex << src.substr(i, 2);
		int byte;
		converter >> byte;
		bytes += byte & 0xFF;
		converter.str(string());
		converter.clear();
	}
	memcpy_s(dest, len, bytes.c_str(), len);
}

/*
* An API for convert char to hexadecimal format
*/
void ConvertorUtils::charToHex(const unsigned char* buffer, unsigned int length)
{
	const ios::fmtflags f(cout.flags());
	cout << hex;
	for (size_t i = 0; i < length; i++)
		cout << setfill('0') << setw(2) <<
		(0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
	cout << endl;
	cout.flags(f);
}