#pragma once
#include <string>
using namespace std;
class ConvertorUtils
{
	ConvertorUtils() = default;
	~ConvertorUtils();
public:
	static void ascii2String(string* dest, const string& src, unsigned int len);
	static string convert_to_string(const char* buffer);
	static string hex2Ascii(const char* arr, size_t len);
	static void ascii2HexBytes(char* dest, const string& src, size_t len);
	static void charToHex(const unsigned char* buffer, unsigned int length);
};

