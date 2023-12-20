#include <string>
using namespace std;

class Base64Convertor
{
public:
	/*Function for encode given string in Base64 format */
	static string encodeStr(const string& str);
	/*Function for decode given string in Base64 format */
	static string decodeStr(const string& str);
};
