#include <CtrlLib/CtrlLib.h>

#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <sodium.h>

using namespace Upp;
using namespace std;
namespace fs = std::filesystem;

static const string VAULT_DIR =
    "C:/Users/pc/Documents/PassKeeper/";

struct AccountData {
    string title;
    string user;
    string password;
};

static bool InitCrypto()
{
    return sodium_init() >= 0;
}

static bool LoadAndDecrypt(
    const string& account,
    const string& master,
    AccountData& result
)
{
    if (!InitCrypto())
        return false;

    ifstream file(VAULT_DIR + account + ".vlt", ios::binary);

    if (!file)
        return false;

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char key[32];

    file.read(reinterpret_cast<char*>(salt), sizeof salt);
    file.read(reinterpret_cast<char*>(nonce), sizeof nonce);

    if (!file)
        return false;

    file.seekg(0, ios::end);

    size_t fileSize = static_cast<size_t>(file.tellg());

    if (fileSize <
        sizeof salt +
        sizeof nonce +
        crypto_secretbox_MACBYTES)
        return false;

    size_t encryptedSize =
        fileSize - sizeof salt - sizeof nonce;

    file.seekg(
        sizeof salt + sizeof nonce,
        ios::beg
    );

    vector<unsigned char> encrypted(encryptedSize);

    file.read(
        reinterpret_cast<char*>(encrypted.data()),
        encryptedSize
    );

    if (!file)
        return false;

    if (crypto_pwhash(
        key,
        sizeof key,
        master.c_str(),
        master.size(),
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13
    ) != 0)
        return false;

    vector<unsigned char> decrypted(
        encryptedSize - crypto_secretbox_MACBYTES
    );

    if (crypto_secretbox_open_easy(
        decrypted.data(),
        encrypted.data(),
        encryptedSize,
        nonce,
        key
    ) != 0)
        return false;

    string data(
        reinterpret_cast<char*>(decrypted.data()),
        decrypted.size()
    );

    size_t p1 = data.find("title: ");
    size_t p2 = data.find("\nuser/email: ");
    size_t p3 = data.find("\npassword: ");

    if (p1 == string::npos ||
        p2 == string::npos ||
        p3 == string::npos)
        return false;

    result.title =
        data.substr(
            p1 + 7,
            p2 - (p1 + 7)
        );

    result.user =
        data.substr(
            p2 + 13,
            p3 - (p2 + 13)
        );

    result.password =
        data.substr(p3 + 11);

    if (!result.password.empty() &&
        result.password.back() == '\n')
        result.password.pop_back();

    return true;
}

static bool AddAccount(
    const string& account,
    const string& master,
    const string& title,
    const string& user,
    const string& password
)
{
    if (!InitCrypto() || account.empty())
        return false;

    fs::create_directories(VAULT_DIR);

    unsigned char key[32];
    unsigned char salt[crypto_pwhash_SALTBYTES];

    randombytes_buf(salt, sizeof salt);

    if (crypto_pwhash(
        key,
        sizeof key,
        master.c_str(),
        master.size(),
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13
    ) != 0)
        return false;

    string data =
        "title: " + title + "\n" +
        "user/email: " + user + "\n" +
        "password: " + password + "\n";

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    vector<unsigned char> encrypted(
        data.size() + crypto_secretbox_MACBYTES
    );

    if (crypto_secretbox_easy(
        encrypted.data(),
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size(),
        nonce,
        key
    ) != 0)
        return false;

    ofstream file(
        VAULT_DIR + account + ".vlt",
        ios::binary | ios::trunc
    );

    if (!file)
        return false;

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

    return static_cast<bool>(file);
}

static bool EditAccount(
    const string& account,
    const string& master,
    const string& title,
    const string& user,
    const string& password
)
{
    if (!InitCrypto())
        return false;

    ifstream file(
        VAULT_DIR + account + ".vlt",
        ios::binary
    );

    if (!file)
        return false;

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char oldNonce[crypto_secretbox_NONCEBYTES];
    unsigned char key[32];

    file.read(
        reinterpret_cast<char*>(salt),
        sizeof salt
    );

    file.read(
        reinterpret_cast<char*>(oldNonce),
        sizeof oldNonce
    );

    if (!file)
        return false;

    file.seekg(0, ios::end);

    size_t fileSize =
        static_cast<size_t>(file.tellg());

    if (fileSize <
        sizeof salt +
        sizeof oldNonce +
        crypto_secretbox_MACBYTES)
        return false;

    size_t encryptedSize =
        fileSize -
        sizeof salt -
        sizeof oldNonce;

    file.seekg(
        sizeof salt + sizeof oldNonce,
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
        master.c_str(),
        master.size(),
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13
    ) != 0)
        return false;

    vector<unsigned char> decrypted(
        encryptedSize - crypto_secretbox_MACBYTES
    );

    if (crypto_secretbox_open_easy(
        decrypted.data(),
        encrypted.data(),
        encryptedSize,
        oldNonce,
        key
    ) != 0)
        return false;

    string data =
        "title: " + title + "\n" +
        "user/email: " + user + "\n" +
        "password: " + password + "\n";

    unsigned char newNonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(newNonce, sizeof newNonce);

    vector<unsigned char> newEncrypted(
        data.size() + crypto_secretbox_MACBYTES
    );

    if (crypto_secretbox_easy(
        newEncrypted.data(),
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size(),
        newNonce,
        key
    ) != 0)
        return false;

    ofstream outFile(
        VAULT_DIR + account + ".vlt",
        ios::binary | ios::trunc
    );

    if (!outFile)
        return false;

    outFile.write(
        reinterpret_cast<const char*>(salt),
        sizeof salt
    );

    outFile.write(
        reinterpret_cast<const char*>(newNonce),
        sizeof newNonce
    );

    outFile.write(
        reinterpret_cast<const char*>(newEncrypted.data()),
        newEncrypted.size()
    );

    return static_cast<bool>(outFile);
}

static bool DeleteAccount(const string& account)
{
    return fs::remove(
        VAULT_DIR + account + ".vlt"
    );
}


// ------------------------------------------------------------
// Small dialog used to enter the account filename/name
// ------------------------------------------------------------

class AccountNameDialog : public TopWindow
{
public:
    EditString name;
    Button ok;
    Button cancel;

    AccountNameDialog()
    {
        Title("Add Account");
        SetRect(0, 0, 360, 120);

        name.SetText("");

        ok.SetLabel("OK");
        cancel.SetLabel("Cancel");

        Add(
            name
                .LeftPos(20, 320)
                .TopPos(20, 30)
        );

        Add(
            ok
                .LeftPos(150, 90)
                .TopPos(65, 30)
        );

        Add(
            cancel
                .LeftPos(250, 90)
                .TopPos(65, 30)
        );

        ok.WhenAction = [=] {
            if (String(~name).IsEmpty())
                return;

            AcceptBreak(IDOK);
        };

        cancel.WhenAction = [=] {
            RejectBreak(IDCANCEL);
        };

        Breaker(IDOK, IDCANCEL);

        CenterScreen();
    }

    String RunDialog()
    {
        if (Run() == IDOK)
            return ~name;

        return Null;
    }
};


// ------------------------------------------------------------
// Main application
// ------------------------------------------------------------

class PassKeeper : public TopWindow
{
private:
    ArrayCtrl accounts;

    Label titleLabel;
    Label userLabel;
    Label passwordLabel;
    Label masterLabel;

    EditString title;
    EditString user;
    EditString password;
    EditString master;

    Button add;
    Button edit;
    Button remove;
    Button copy;

    void LoadAccounts()
    {
        accounts.Clear();

        fs::create_directories(VAULT_DIR);

        for (const auto& entry :
             fs::directory_iterator(VAULT_DIR))
        {
            if (!entry.is_regular_file())
                continue;

            if (entry.path().extension() != ".vlt")
                continue;

            accounts.Add(
                entry.path().stem().string()
            );
        }
    }

    string SelectedAccount() const
    {
        if (!accounts.IsCursor())
            return {};

        Value value = accounts.Get(0);

        return value.ToStd();
    }

    string GetField(EditString& field)
    {
        return String(~field).ToStd();
    }

    void ClearFields()
    {
        title.Clear();
        user.Clear();
        password.Clear();
    }

    void LoadSelectedAccount()
    {
        string account = SelectedAccount();

        if (account.empty())
            return;

        string masterKey = GetField(master);

        if (masterKey.empty()) {
            PromptOK("Enter the master-key first.");
            return;
        }

        AccountData data;

        if (!LoadAndDecrypt(
            account,
            masterKey,
            data
        )) {
            PromptOK("Wrong master-key or corrupted account.");
            return;
        }

        title <<= data.title;
        user <<= data.user;
        password <<= data.password;
    }

    void AddClicked()
    {
        AccountNameDialog dialog;

        String accountName = dialog.RunDialog();

        if (accountName.IsNull())
            return;

        string account = accountName.ToStd();

        string masterKey = GetField(master);
        string titleValue = GetField(title);
        string userValue = GetField(user);
        string passwordValue = GetField(password);

        if (masterKey.empty() ||
            titleValue.empty() ||
            userValue.empty() ||
            passwordValue.empty()) {
            PromptOK("Fill all fields first.");
            return;
        }

        if (fs::exists(VAULT_DIR + account + ".vlt")) {
            PromptOK("That account already exists.");
            return;
        }

        if (!AddAccount(
            account,
            masterKey,
            titleValue,
            userValue,
            passwordValue
        )) {
            PromptOK("Failed to create account.");
            return;
        }

        LoadAccounts();

        PromptOK("Account added.");
    }

    void EditClicked()
    {
        string account = SelectedAccount();

        if (account.empty()) {
            PromptOK("Select an account first.");
            return;
        }

        string masterKey = GetField(master);
        string titleValue = GetField(title);
        string userValue = GetField(user);
        string passwordValue = GetField(password);

        if (masterKey.empty() ||
            titleValue.empty() ||
            userValue.empty() ||
            passwordValue.empty()) {
            PromptOK("Fill all fields first.");
            return;
        }

        if (!EditAccount(
            account,
            masterKey,
            titleValue,
            userValue,
            passwordValue
        )) {
            PromptOK("Wrong master-key or edit failed.");
            return;
        }

        PromptOK("Account updated.");
    }

    void DeleteClicked()
    {
        string account = SelectedAccount();

        if (account.empty()) {
            PromptOK("Select an account first.");
            return;
        }

        if (!DeleteAccount(account)) {
            PromptOK("Could not delete account.");
            return;
        }

        LoadAccounts();
        ClearFields();

        PromptOK("Account deleted.");
    }

    void CopyClicked()
    {
        if (password.IsEmpty())
            return;

        WriteClipboardText(password.GetData());

        PromptOK("Password copied.");
    }

public:
    PassKeeper()
    {
        Title("PassKeeper");

        SetRect(0, 0, 800, 500);

        Sizeable().Zoomable();

        // Account list
        accounts.AddColumn("Account");
        accounts.ColumnWidths("220");

        // Labels
        titleLabel.SetText("Title");
        userLabel.SetText("Username / Email");
        passwordLabel.SetText("Password");
        masterLabel.SetText("Master Key");

        // Buttons
        add.SetLabel("Add Account");
        edit.SetLabel("Edit");
        remove.SetLabel("Delete");
        copy.SetLabel("Copy Password");

        // Password fields
        password.Password(true);
        master.Password(true);

        // Left side
        Add(
            accounts
                .LeftPos(20, 220)
                .TopPos(55, 360)
        );

        // Right side
        Add(
            titleLabel
                .LeftPos(270, 180)
                .TopPos(20, 25)
        );

        Add(
            title
                .LeftPos(270, 480)
                .TopPos(45, 30)
        );

        Add(
            userLabel
                .LeftPos(270, 180)
                .TopPos(90, 25)
        );

        Add(
            user
                .LeftPos(270, 480)
                .TopPos(115, 30)
        );

        Add(
            passwordLabel
                .LeftPos(270, 180)
                .TopPos(160, 25)
        );

        Add(
            password
                .LeftPos(270, 480)
                .TopPos(185, 30)
        );

        Add(
            masterLabel
                .LeftPos(270, 180)
                .TopPos(240, 25)
        );

        Add(
            master
                .LeftPos(270, 480)
                .TopPos(265, 30)
        );

        Add(
            add
                .LeftPos(270, 130)
                .TopPos(320, 35)
        );

        Add(
            edit
                .LeftPos(410, 80)
                .TopPos(320, 35)
        );

        Add(
            remove
                .LeftPos(500, 80)
                .TopPos(320, 35)
        );

        Add(
            copy
                .LeftPos(270, 140)
                .TopPos(365, 35)
        );

        // Events
        accounts.WhenSel = [=] {
            LoadSelectedAccount();
        };

        add.WhenAction = [=] {
            AddClicked();
        };

        edit.WhenAction = [=] {
            EditClicked();
        };

        remove.WhenAction = [=] {
            DeleteClicked();
        };

        copy.WhenAction = [=] {
            CopyClicked();
        };

        LoadAccounts();
    }
};

GUI_APP_MAIN
{
    PassKeeper().Run();
}