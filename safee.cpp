#include<iostream>
#include<fstream>
#include<string>
#include<cstring>
#include<filesystem>
#include<sodium.h>
#include <vector>

using namespace std;
void AddAccount(string Account){
    string password,user,title,master,password0;
    cout<<"Enter master-key: ";
    cin>>password0;
if (sodium_init() < 0) {
    return;
}
    unsigned char key[32];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof salt);
if (crypto_pwhash(
    key,
    sizeof key,
    password0.c_str(),
    password0.size(),
    salt,
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_ALG_ARGON2ID13
) != 0) {
    return;
}
    filesystem::create_directory("C:/Users/pc/Documents/PassKeeper");
    cout<<"title: ";
    cin>>title;
    cout<<"user: ";
    cin>>user;
    cout<<"password: ";
    cin>>password;   
string data =
    "title: " + title + "\n" +
    "user/email: " + user + "\n" +
    "password: " + password + "\n";

unsigned char nonce[crypto_secretbox_NONCEBYTES];
randombytes_buf(nonce, sizeof nonce);

vector<unsigned char> encrypted(
    data.size() + crypto_secretbox_MACBYTES
);

crypto_secretbox_easy(
    encrypted.data(),
    reinterpret_cast<const unsigned char*>(data.data()),
    data.size(),
    nonce,
    key
);
ofstream file(
    "C:/Users/pc/Documents/PassKeeper/" + Account + ".vlt",
    ios::binary
);

file.write(
    reinterpret_cast<const char*>(salt),
    sizeof salt
);

file.write(
    reinterpret_cast<const char*>(nonce),
    sizeof nonce
);

file.write(
    reinterpret_cast<const char*>(encrypted.data()),
    encrypted.size()
);
file.close();
}
void EditAccount(string Account){
    string password,user,title;
    ofstream file ("C:/Users/pc/Documents/PassKeeper/"+Account+".vlt");
    cout<<"new title: ";
    cin>>title;
    cout<<"new user: ";
    cin>>user;
    cout<<"new password: ";
    cin>>password;   
    file<<"title: "<<title<<"\n";
    file<<"user/email: "<<user<<"\n";
    file<<"password: "<<password<<"\n";
    file.close();    
}
void ReadAccount(string Account) {
    string password0;

    cout << "Enter master-key: ";
    cin >> password0;

    ifstream file(
        "C:/Users/pc/Documents/PassKeeper/" + Account + ".vlt",
        ios::binary
    );

    if (!file) {
        cout << "Account not found." << endl;
        return;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char key[32];

    file.read(
        reinterpret_cast<char*>(salt),
        sizeof salt
    );

    file.read(
        reinterpret_cast<char*>(nonce),
        sizeof nonce
    );

    file.seekg(0, ios::end);
    size_t fileSize = static_cast<size_t>(file.tellg());

    size_t encryptedSize =
        fileSize -
        sizeof salt -
        sizeof nonce;

    file.seekg(
        sizeof salt + sizeof nonce,
        ios::beg
    );

    vector<unsigned char> encrypted(encryptedSize);

    file.read(
        reinterpret_cast<char*>(encrypted.data()),
        encryptedSize
    );

    file.close();

if (crypto_pwhash(
    key,
    sizeof key,
    password0.c_str(),
    password0.size(),
    salt,
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_ALG_ARGON2ID13
) != 0) {
    cout << "Key generation failed." << endl;
    return;
}

    vector<unsigned char> decrypted(
        encryptedSize - crypto_secretbox_MACBYTES
    );

    if (crypto_secretbox_open_easy(
            decrypted.data(),
            encrypted.data(),
            encryptedSize,
            nonce,
            key
        ) != 0) {

        cout << "Wrong master-key." << endl;
        return;
    }

    cout << string(
        reinterpret_cast<char*>(decrypted.data()),
        decrypted.size()
    );
}
void DeleteAccount(string Account){
    filesystem::remove("C:/Users/pc/Documents/PassKeeper/"+Account+".vlt");
}

int main(int argc,char* argv[]){
    if(argc != 3){
        cout<<"Please use: './safee <Action> <AccountName>'"<<endl;
        return 1;
    }
    string action = argv[1];
    string account = argv[2];
    if(strcmp(action.c_str(),"add")==0){
        AddAccount(account);
    } else if (strcmp(action.c_str(),"edit")==0){
        EditAccount(account);
    } else if(strcmp(action.c_str(),"rm")==0){
        DeleteAccount(account);
    } else if(strcmp(action.c_str(),"rd")==0){
        ReadAccount(account);
    }
   return 0;
}