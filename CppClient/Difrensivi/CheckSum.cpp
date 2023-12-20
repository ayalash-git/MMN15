#include "Utils.h"
#include "CheckSum.h"
using namespace std;

CheckSum::CheckSum() {

}
CheckSum::~CheckSum()
{
}

uint32_t* CheckSum::getCrcData()
{
    return _crcData;
}
  
unsigned long CheckSum::memcrc(char* b, size_t n) {
    unsigned int v = 0, c = 0;
    unsigned long s = 0;
    unsigned int tabidx;

    for (int i = 0; i < n; i++) {
        tabidx = (s >> 24) ^ (unsigned char)b[i];
        s = UNSIGNED((s << 8)) ^CheckSum::_crcData[tabidx];
    }

    while (n) {
        c = n & 0377;
        n = n >> 8;
        s = UNSIGNED(s << 8) ^ CheckSum::_crcData[(s >> 24) ^ c];
    }
    return (unsigned long)UNSIGNED(~s);

}

string CheckSum::getFileCheckSum(string fname) {
    if (filesystem::exists(fname)) {
        filesystem::path fpath = fname;
        ifstream f1(fname.c_str(), ios::binary);

        size_t size = filesystem::file_size(fpath);
        char* b = new char[size];
        f1.seekg(0, ios::beg);
        f1.read(b, size);
        cout << "tellg returns" << f1.tellg() << endl;

        return to_string(CheckSum::memcrc(b, size)) + '\t' + to_string(size) + '\t' + fname;
    }
    else {
        cerr << "Cannot open input file " << fname << endl;
        return "";
    }
}
