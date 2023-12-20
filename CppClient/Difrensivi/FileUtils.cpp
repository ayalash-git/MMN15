
#include <iostream>
#include <fstream>
#include "FileUtils.h"
#include <string>
using namespace std;

FileUtils::~FileUtils()
{
}

ofstream FileUtils::open_out_file(const string& filename)
{
	ofstream file;
	file.open(filename);
	if (!file)
	{
		cout << "Error in file: " << filename << ". ";
		throw exception("File does not exist");
	}
	return file;
}
/*
* An API for open file for read (input)
* Return File stream to read from
*/
ifstream FileUtils::open_input_file(const string& fileName)
{
	ifstream file;

	file.open(fileName);
	if (!file) //File not found
	{
		const string err = "Cannot open file: " + fileName;
		throw exception(err.c_str());
	}

	return file;
}

//This function reads the contents of the file into a string
string FileUtils::get_file_content(string filename)
{
	string content;
	//open a file throw an exception when file not exist
	ifstream file = open_input_file(filename);

	while (!file.eof())
	{
		getline(file, content);
	}
	file.close();
	cout << "The length of the file " << filename << " is: " << content.size() << endl;
	return content;
}