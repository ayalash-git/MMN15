#pragma once
#include <string.h>
using namespace std;
class FileUtils
{
	FileUtils() = default;
	~FileUtils();
public:
	//Open an output file , verify if file exist return file stream
	static ofstream open_out_file(const string& filename);
	//open input file , verify if file exist return input file stream
	static ifstream open_input_file(const string& filename);
	//This function reads the contents of the file into a string
	static string get_file_content(string filename);
};
