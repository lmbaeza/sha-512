#include <bits/stdc++.h>

using namespace std;


class SHA512{
private:
    const uint64_t h_primes[8] = {  
        0x6a09e667f3bcc908ULL, 
        0xbb67ae8584caa73bULL, 
        0x3c6ef372fe94f82bULL, 
        0xa54ff53a5f1d36f1ULL, 
        0x510e527fade682d1ULL, 
        0x9b05688c2b3e6c1fULL, 
        0x1f83d9abfb41bd6bULL, 
        0x5be0cd19137e2179ULL
    };

    const uint64_t K[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 
        0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 
        0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 
        0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL, 
        0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 
        0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 
        0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL, 
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL, 
        0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 
        0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 
        0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL, 
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL, 
        0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 
        0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 
        0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };

    static const unsigned int SEQUENCE_LEN = (1024/64);

    uint64_t** preprocess(const unsigned char* input, size_t& nBuffer);
    void appendLen(uint64_t mLen, uint64_t mp, uint64_t& lo, uint64_t& hi);
    void process(uint64_t** buffer, size_t nBuffer, uint64_t* h);
    string digest(uint64_t* h);
    void print_padding(uint64_t** buffer, size_t nBuffer);
    void freeBuffer(uint64_t** buffer, size_t nBuffer);

public:
    string hash(const string input);

    SHA512();
    ~SHA512();
};

#define Ch(x,y,z) ((x&y)^(~x&z))
#define Maj(x,y,z) ((x&y)^(x&z)^(y&z))
#define RotR(x, n) ((x>>n)|(x<<((sizeof(x)<<3)-n)))
#define Sig0(x) ((RotR(x, 28))^(RotR(x,34))^(RotR(x, 39)))
#define Sig1(x) ((RotR(x, 14))^(RotR(x,18))^(RotR(x, 41)))
#define sig0(x) (RotR(x, 1)^RotR(x,8)^(x>>7))
#define sig1(x) (RotR(x, 19)^RotR(x,61)^(x>>6))

typedef unsigned __int128 uint128;

SHA512::SHA512() {}

SHA512::~SHA512() {}

template<typename T>
string int_to_hex(T number, int dig) {
    assert(is_integral<T>::value);
    stringstream stream;
    stream << hex << number;
    string result(stream.str());
    string zeros="";
    for(int i = 0; i < dig - int(result.size()); ++i) zeros += "0";
    return zeros + result;
}

string SHA512::hash(const string input) {
    size_t nBuffer; //amt of message blocks
    uint64_t** buffer; //message blocks of size 1024bits wtih 16 64bit words
    uint64_t* h = new uint64_t[8];
    buffer = preprocess((unsigned char*)input.c_str(), nBuffer);
    process(buffer, nBuffer, h);
    freeBuffer(buffer, nBuffer);
    return digest(h);
}

void SHA512::print_padding(uint64_t** buffer, size_t nBuffer) {
    cout << "\nPadding" << endl;
    for(int i = 0; i < int(nBuffer); ++i) {
        for(int j = 0; j < int(SEQUENCE_LEN); ++j) {
            if(buffer[i][j] < 16) {
                cout << hex << 0 << buffer[i][j];
            } else {
                cout << hex << buffer[i][j];
            }
        }
    }
    cout << endl << endl;
}

uint64_t** SHA512::preprocess(const unsigned char* input, size_t &nBuffer) {
    size_t mLen = strlen((const char*) input);
    size_t kLen = (895-(mLen*8))%1024;
    nBuffer = (mLen*8+1+kLen+128) / 1024;

    uint64_t** buffer = new uint64_t*[nBuffer];

    for(size_t i=0; i<nBuffer; i++) {
        buffer[i] = new uint64_t[SEQUENCE_LEN];
    }

    for(size_t i=0; i<nBuffer; i++) {
        for(size_t j=0; j<SEQUENCE_LEN; j++) {
            uint64_t in = 0x0ULL;
            for(size_t k=0; k<8; k++) {
                if(i*128+j*8+k < mLen) {
                    in = in << 8 | (uint64_t)input[i*128+j*8+k];
                } else if(i*128+j*8+k == mLen) {
                    in = in << 8 | 0x80ULL;
                } else {
                    in = in << 8 | 0x0ULL;
                }
            }
            buffer[i][j] = in;
        }
    }
    appendLen(mLen, 8, buffer[nBuffer-1][SEQUENCE_LEN-1], buffer[nBuffer-1][SEQUENCE_LEN-2]);
    print_padding(buffer, nBuffer);
    return buffer;
}

void SHA512::process(uint64_t** buffer, size_t nBuffer, uint64_t* h){
    uint64_t s[8];
    uint64_t w[80];

    memcpy(h, h_primes, 8*sizeof(uint64_t));

    for(size_t i=0; i<nBuffer; i++) {
        //message schedule
        memcpy(w, buffer[i], 16*sizeof(uint64_t));

        for(size_t j = 16; j < 80; j++) {
            w[j] = w[j-16] + sig0(w[j-15]) + w[j-7] + sig1(w[j-2]);
        }
        //init
        memcpy(s, h, 8*sizeof(uint64_t));
        //compression
        for(size_t j=0; j<80; j++) {
            uint64_t temp1 = s[7] + Sig1(s[4]) + Ch(s[4], s[5], s[6]) + K[j] + w[j];
            uint64_t temp2 = Sig0(s[0]) + Maj(s[0], s[1], s[2]);
            s[7] = s[6];
            s[6] = s[5];
            s[5] = s[4];
            s[4] = s[3] + temp1;
            s[3] = s[2];
            s[2] = s[1];
            s[1] = s[0];
            s[0] = temp1 + temp2;
        }
        for(size_t j=0; j < 8; j++) {
            h[j] += s[j];
        }
    }

}

void SHA512::appendLen(uint64_t mLen, uint64_t mp, uint64_t& lo, uint64_t& hi){
    // Poner la longitud de la cadena en el padding
    uint128 prod = mLen*mp;
    lo = prod;
    hi = prod>>64;
}

string SHA512::digest(uint64_t* h) {
    // stringstream ss;
    // for(size_t i=0; i<8; i++) {
    //     ss << hex << h[i];
    // }
    // delete[] h;
    // return ss.str();

    string answer = "";
    for(size_t i=0; i < 8; i++) {
    	answer += int_to_hex<int64_t>(h[i], 16);
    }
    delete[] h;
    return answer;
}

void SHA512::freeBuffer(uint64_t** buffer, size_t nBuffer) {
    for(size_t i=0; i<nBuffer; i++){
        delete[] buffer[i];
    }
    delete[] buffer;
}

string string_to_hex(const string &s) {
    string answer = "";
    int n = int(s.size());
    for(int i = 0; i < n; ++i){
        int ascii = s[i];
        answer += int_to_hex(ascii);
    }
    return answer;
}

int hex_to_int(string hx) {
    int answer;   
    std::stringstream ss;
    ss << std::hex << hx;
    ss >> answer;
    return answer;
}

string hex_to_string(string s) {
    string answer = "";
    int n = int(s.size());
    if(int(s.size()) & 1) {
        s = "0" + s;
    }
    for(int i = 0; i < n; i += 2) {
        string S;
        S.push_back(s[i]);
        S.push_back(s[i+1]);
        int ascii = hex_to_int(S);
        answer.push_back((((char)ascii)));
    }
    return answer;
}

int main(){
    SHA512 sha512;
    stringstream ss;
    ss << "Introduccion a la criptografia y seguridad de la informacion.";

    string hash1 = sha512.hash(ss.str());

    cout << "Hash1: [ " << hash1 << " ]" << endl;

    cout << int(hash1.size()) << endl;

    string hash2 = sha512.hash(hex_to_string(hash1));

    cout << "Hash2: [ " << hash2 << " ]" << endl;

    //cout << hash2 << endl;

    /*
    uint64_t number = 81985529216486895;

    uint64_t ans1 = Sig0(number);

    cout << "Sig0: " << ans1 << endl;
    */
    return 0;
}

// https://github.com/pr0f3ss/SHA512