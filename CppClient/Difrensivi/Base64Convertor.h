#include <string>
using namespace std;

class Base64Convertor
{
public:
	static string encodeStr(const string& str);
	static string decodeStr(const string& str);
};
