#include "PhoneUnlockCredential.h"
#include "PhoneUnlockProvider.h"
#include "helpers.h"

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <ntsecapi.h>

#include <new>
#include <cwchar>
#include <cstring>
#include <string>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")


// ============================================================
// Configuration
// ============================================================

static const wchar_t* SERVER_HOST =
L"127.0.0.1";

static const INTERNET_PORT SERVER_PORT =
3000;

static const wchar_t* PAIRING_FILE =
L"C:\\PhoneUnlock\\windows-client\\pairing.json";


// ============================================================
// Read UTF-8 text file
// ============================================================

static std::wstring ReadTextFile(
    const wchar_t* path
)
{
    HANDLE file =
        CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

    if (file == INVALID_HANDLE_VALUE)
        return L"";

    DWORD size =
        GetFileSize(
            file,
            nullptr
        );

    if (
        size == INVALID_FILE_SIZE ||
        size == 0
        )
    {
        CloseHandle(file);
        return L"";
    }

    std::string buffer(
        size,
        '\0'
    );

    DWORD bytesRead = 0;

    BOOL ok =
        ReadFile(
            file,
            buffer.data(),
            size,
            &bytesRead,
            nullptr
        );

    CloseHandle(file);

    if (
        !ok ||
        bytesRead == 0
        )
    {
        return L"";
    }

    int length =
        MultiByteToWideChar(
            CP_UTF8,
            0,
            buffer.data(),
            bytesRead,
            nullptr,
            0
        );

    if (length <= 0)
        return L"";

    std::wstring result(
        length,
        L'\0'
    );

    MultiByteToWideChar(
        CP_UTF8,
        0,
        buffer.data(),
        bytesRead,
        result.data(),
        length
    );

    return result;
}


// ============================================================
// Simple JSON string extractor
// ============================================================

static std::wstring ExtractJsonString(
    const std::wstring& json,
    const std::wstring& key
)
{
    std::wstring search =
        L"\"" +
        key +
        L"\"";

    size_t keyPosition =
        json.find(
            search
        );

    if (
        keyPosition ==
        std::wstring::npos
        )
    {
        return L"";
    }

    size_t colon =
        json.find(
            L':',
            keyPosition +
            search.length()
        );

    if (
        colon ==
        std::wstring::npos
        )
    {
        return L"";
    }

    size_t firstQuote =
        json.find(
            L'"',
            colon + 1
        );

    if (
        firstQuote ==
        std::wstring::npos
        )
    {
        return L"";
    }

    size_t secondQuote =
        json.find(
            L'"',
            firstQuote + 1
        );

    if (
        secondQuote ==
        std::wstring::npos
        )
    {
        return L"";
    }

    return json.substr(
        firstQuote + 1,
        secondQuote -
        firstQuote -
        1
    );
}


// ============================================================
// Cryptographic challenge
// ============================================================

static std::wstring CreateChallenge()
{
    BYTE bytes[32];

    NTSTATUS status =
        BCryptGenRandom(
            nullptr,
            bytes,
            sizeof(bytes),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );

    if (status != 0)
        return L"";

    static const wchar_t* hex =
        L"0123456789abcdef";

    std::wstring result;

    result.reserve(
        sizeof(bytes) * 2
    );

    for (
        size_t i = 0;
        i < sizeof(bytes);
        ++i
        )
    {
        result +=
            hex[
                (bytes[i] >> 4) &
                    0x0F
            ];

        result +=
            hex[
                bytes[i] &
                    0x0F
            ];
    }

    return result;
}


// ============================================================
// Status text
// ============================================================

static void SetStatusText(
    ICredentialProviderCredentialEvents* events,
    ICredentialProviderCredential* credential,
    const wchar_t* text
)
{
    if (
        !events ||
        !credential ||
        !text
        )
    {
        return;
    }

    events->SetFieldString(
        credential,
        FIELD_STATUS,
        text
    );
}


// ============================================================
// HTTPS certificate handling
// ============================================================

static void ConfigureSecureRequest(
    HINTERNET request
)
{
    if (!request)
        return;

    DWORD securityFlags =
        SECURITY_FLAG_IGNORE_UNKNOWN_CA |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;

    WinHttpSetOption(
        request,
        WINHTTP_OPTION_SECURITY_FLAGS,
        &securityFlags,
        sizeof(securityFlags)
    );
}


// ============================================================
// HTTPS GET
// ============================================================

static std::wstring HttpGet(
    const std::wstring& path,
    const std::wstring& pairSecret
)
{
    std::wstring result;

    HINTERNET session =
        WinHttpOpen(
            L"PhoneUnlockCredentialProvider/1.0",
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );

    if (!session)
        return L"";

    WinHttpSetTimeouts(
        session,
        3000,
        3000,
        3000,
        3000
    );

    HINTERNET connection =
        WinHttpConnect(
            session,
            SERVER_HOST,
            SERVER_PORT,
            0
        );

    if (!connection)
    {
        WinHttpCloseHandle(session);
        return L"";
    }

    HINTERNET request =
        WinHttpOpenRequest(
            connection,
            L"GET",
            path.c_str(),
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE
        );

    if (!request)
    {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return L"";
    }

    ConfigureSecureRequest(
        request
    );

    std::wstring authorization =
        L"Authorization: Bearer " +
        pairSecret +
        L"\r\n";

    BOOL sent =
        WinHttpSendRequest(
            request,
            authorization.c_str(),
            static_cast<DWORD>(-1L),
            nullptr,
            0,
            0,
            0
        );

    BOOL received = FALSE;

    if (sent)
    {
        received =
            WinHttpReceiveResponse(
                request,
                nullptr
            );
    }

    if (received)
    {
        DWORD available = 0;

        while (
            WinHttpQueryDataAvailable(
                request,
                &available
            ) &&
            available > 0
            )
        {
            std::string buffer(
                available,
                '\0'
            );

            DWORD bytesRead = 0;

            if (
                !WinHttpReadData(
                    request,
                    buffer.data(),
                    available,
                    &bytesRead
                )
                )
            {
                break;
            }

            if (bytesRead == 0)
                break;

            int wideLength =
                MultiByteToWideChar(
                    CP_UTF8,
                    0,
                    buffer.data(),
                    bytesRead,
                    nullptr,
                    0
                );

            if (wideLength <= 0)
                continue;

            std::wstring wide(
                wideLength,
                L'\0'
            );

            MultiByteToWideChar(
                CP_UTF8,
                0,
                buffer.data(),
                bytesRead,
                wide.data(),
                wideLength
            );

            result += wide;
        }
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);

    return result;
}


// ============================================================
// Constructor
// ============================================================

PhoneUnlockCredential::PhoneUnlockCredential(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus
)
    :
    _refCount(1),
    _events(nullptr),
    _cpus(cpus),
    _approvalThread(nullptr),
    _approvalThreadRunning(0),
    _approved(0),
    _requestId(),
    _pairSecret(),
    _username(L"petma"),
    _password()
{
    InterlockedIncrement(
        &g_dllObjectCount
    );
}


// ============================================================
// Destructor
// ============================================================

PhoneUnlockCredential::~PhoneUnlockCredential()
{
    if (_approvalThread)
    {
        CloseHandle(
            _approvalThread
        );

        _approvalThread = nullptr;
    }

    if (!_password.empty())
    {
        SecureZeroMemory(
            _password.data(),
            _password.size() *
            sizeof(wchar_t)
        );

        _password.clear();
    }

    if (!_pairSecret.empty())
    {
        SecureZeroMemory(
            _pairSecret.data(),
            _pairSecret.size() *
            sizeof(wchar_t)
        );

        _pairSecret.clear();
    }

    if (_events)
    {
        _events->Release();
        _events = nullptr;
    }

    InterlockedDecrement(
        &g_dllObjectCount
    );
}


// ============================================================
// IUnknown
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::QueryInterface(
    REFIID riid,
    void** ppvObject
)
{
    if (!ppvObject)
        return E_POINTER;

    *ppvObject = nullptr;

    if (
        riid == IID_IUnknown ||
        riid == IID_ICredentialProviderCredential
        )
    {
        *ppvObject =
            static_cast<
            ICredentialProviderCredential*
            >(this);

        AddRef();

        return S_OK;
    }

    return E_NOINTERFACE;
}


ULONG STDMETHODCALLTYPE
PhoneUnlockCredential::AddRef()
{
    return InterlockedIncrement(
        &_refCount
    );
}


ULONG STDMETHODCALLTYPE
PhoneUnlockCredential::Release()
{
    LONG refCount =
        InterlockedDecrement(
            &_refCount
        );

    if (refCount == 0)
    {
        delete this;
    }

    return refCount;
}


// ============================================================
// Events
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::Advise(
    ICredentialProviderCredentialEvents* pcpce
)
{
    if (_events)
    {
        _events->Release();
        _events = nullptr;
    }

    if (pcpce)
    {
        _events = pcpce;
        _events->AddRef();
    }

    return S_OK;
}


HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::UnAdvise()
{
    if (_events)
    {
        _events->Release();
        _events = nullptr;
    }

    return S_OK;
}


// ============================================================
// Selection
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::SetSelected(
    BOOL* pbAutoLogon
)
{
    if (!pbAutoLogon)
        return E_POINTER;

    *pbAutoLogon = FALSE;

    return S_OK;
}


HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::SetDeselected()
{
    return S_OK;
}


// ============================================================
// Field state
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
)
{
    if (
        !pcpfs ||
        !pcpfis
        )
    {
        return E_POINTER;
    }

    if (dwFieldID >= FIELD_COUNT)
        return E_INVALIDARG;

    *pcpfis =
        CPFIS_NONE;

    switch (dwFieldID)
    {
    case FIELD_TITLE:

        *pcpfs =
            CPFS_DISPLAY_IN_BOTH;

        return S_OK;

    case FIELD_USERNAME:

        *pcpfs =
            CPFS_DISPLAY_IN_BOTH;

        *pcpfis =
            CPFIS_FOCUSED;

        return S_OK;

    case FIELD_PASSWORD:

        *pcpfs =
            CPFS_DISPLAY_IN_BOTH;

        return S_OK;

    case FIELD_STATUS:

        *pcpfs =
            CPFS_DISPLAY_IN_BOTH;

        return S_OK;

    case FIELD_BUTTON:

        *pcpfs =
            CPFS_DISPLAY_IN_BOTH;

        return S_OK;
    }

    return E_INVALIDARG;
}


// ============================================================
// String values
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::GetStringValue(
    DWORD dwFieldID,
    PWSTR* ppwsz
)
{
    if (!ppwsz)
        return E_POINTER;

    *ppwsz = nullptr;

    std::wstring value;

    switch (dwFieldID)
    {
    case FIELD_TITLE:

        value =
            L"PhoneUnlock";

        break;

    case FIELD_USERNAME:

        value =
            _username;

        break;

    case FIELD_PASSWORD:

        value =
            _password;

        break;

    case FIELD_STATUS:

        if (
            InterlockedCompareExchange(
                &_approved,
                0,
                0
            ) != 0
            )
        {
            value =
                L"Telefon schvalil prihlaseni. Nyni stiskni Enter.";
        }
        else
        {
            value =
                L"Schval prihlaseni pomoci telefonu.";
        }

        break;

    case FIELD_BUTTON:

        value =
            L"Schvalit prihlaseni telefonem";

        break;

    default:

        return E_INVALIDARG;
    }

    size_t bytes =
        (value.length() + 1) *
        sizeof(wchar_t);

    PWSTR result =
        static_cast<PWSTR>(
            CoTaskMemAlloc(
                bytes
            )
            );

    if (!result)
        return E_OUTOFMEMORY;

    memcpy(
        result,
        value.c_str(),
        bytes
    );

    *ppwsz =
        result;

    return S_OK;
}


// ============================================================
// Bitmap
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::GetBitmapValue(
    DWORD,
    HBITMAP* phbmp
)
{
    if (!phbmp)
        return E_POINTER;

    *phbmp = nullptr;

    return E_NOTIMPL;
}


// ============================================================
// Checkbox
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::GetCheckboxValue(
    DWORD,
    BOOL* pbChecked,
    PWSTR* ppwszLabel
)
{
    if (
        !pbChecked ||
        !ppwszLabel
        )
    {
        return E_POINTER;
    }

    *pbChecked = FALSE;
    *ppwszLabel = nullptr;

    return E_NOTIMPL;
}


HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::SetCheckboxValue(
    DWORD,
    BOOL
)
{
    return E_NOTIMPL;
}


// ============================================================
// Submit button
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::GetSubmitButtonValue(
    DWORD dwFieldID,
    DWORD* pdwAdjacentTo
)
{
    if (!pdwAdjacentTo)
        return E_POINTER;

    if (dwFieldID != FIELD_BUTTON)
        return E_INVALIDARG;

    *pdwAdjacentTo =
        FIELD_PASSWORD;

    return S_OK;
}


// ============================================================
// Combo box
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::GetComboBoxValueCount(
    DWORD,
    DWORD* pcItems,
    DWORD* pdwSelectedItem
)
{
    if (
        !pcItems ||
        !pdwSelectedItem
        )
    {
        return E_POINTER;
    }

    *pcItems = 0;
    *pdwSelectedItem = 0;

    return S_OK;
}


HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::GetComboBoxValueAt(
    DWORD,
    DWORD,
    PWSTR* ppwszItem
)
{
    if (!ppwszItem)
        return E_POINTER;

    *ppwszItem = nullptr;

    return E_INVALIDARG;
}


HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::SetComboBoxSelectedValue(
    DWORD,
    DWORD
)
{
    return E_NOTIMPL;
}


// ============================================================
// String setter
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::SetStringValue(
    DWORD dwFieldID,
    PCWSTR pwz
)
{
    if (!pwz)
        return E_INVALIDARG;

    switch (dwFieldID)
    {
    case FIELD_USERNAME:

        _username =
            pwz;

        return S_OK;

    case FIELD_PASSWORD:

        if (!_password.empty())
        {
            SecureZeroMemory(
                _password.data(),
                _password.size() *
                sizeof(wchar_t)
            );
        }

        _password =
            pwz;

        return S_OK;

    default:

        return E_INVALIDARG;
    }
}


// ============================================================
// Approval worker
// ============================================================

DWORD WINAPI
PhoneUnlockCredential::ApprovalThreadProc(
    LPVOID parameter
)
{
    PhoneUnlockCredential* credential =
        static_cast<PhoneUnlockCredential*>(
            parameter
            );

    if (!credential)
        return 0;

    credential->AddRef();

    for (int i = 0; i < 60; ++i)
    {
        Sleep(1000);

        std::wstring requestId =
            credential->_requestId;

        std::wstring pairSecret =
            credential->_pairSecret;

        if (
            requestId.empty() ||
            pairSecret.empty()
            )
        {
            break;
        }

        std::wstring path =
            L"/auth/request/" +
            requestId;

        std::wstring response =
            HttpGet(
                path,
                pairSecret
            );

        if (
            response.find(
                L"\"status\":\"approved\""
            ) != std::wstring::npos
            )
        {
            InterlockedExchange(
                &credential->_approved,
                1
            );

            if (credential->_events)
            {
                SetStatusText(
                    credential->_events,
                    credential,
                    L"Telefon schvalil prihlaseni. Nyni stiskni Enter."
                );
            }

            InterlockedExchange(
                &credential->_approvalThreadRunning,
                0
            );

            credential->Release();

            return 0;
        }

        if (
            response.find(
                L"\"status\":\"denied\""
            ) != std::wstring::npos
            )
        {
            InterlockedExchange(
                &credential->_approved,
                0
            );

            if (credential->_events)
            {
                SetStatusText(
                    credential->_events,
                    credential,
                    L"Telefon zamitl prihlaseni."
                );
            }

            InterlockedExchange(
                &credential->_approvalThreadRunning,
                0
            );

            credential->Release();

            return 0;
        }

        if (
            response.find(
                L"\"status\":\"expired\""
            ) != std::wstring::npos
            )
        {
            InterlockedExchange(
                &credential->_approved,
                0
            );

            if (credential->_events)
            {
                SetStatusText(
                    credential->_events,
                    credential,
                    L"Pozadavek vyprsel."
                );
            }

            InterlockedExchange(
                &credential->_approvalThreadRunning,
                0
            );

            credential->Release();

            return 0;
        }
    }

    InterlockedExchange(
        &credential->_approved,
        0
    );

    if (credential->_events)
    {
        SetStatusText(
            credential->_events,
            credential,
            L"Cas pro schvaleni vyprsel."
        );
    }

    InterlockedExchange(
        &credential->_approvalThreadRunning,
        0
    );

    credential->Release();

    return 0;
}


// ============================================================
// Phone approval command
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::CommandLinkClicked(
    DWORD dwFieldID
)
{
    if (dwFieldID != FIELD_BUTTON)
        return E_INVALIDARG;

    if (
        InterlockedCompareExchange(
            &_approvalThreadRunning,
            1,
            0
        ) != 0
        )
    {
        if (_events)
        {
            SetStatusText(
                _events,
                this,
                L"Pozadavek uz probiha."
            );
        }

        return S_OK;
    }

    InterlockedExchange(
        &_approved,
        0
    );

    if (_events)
    {
        SetStatusText(
            _events,
            this,
            L"Odesilam pozadavek do telefonu..."
        );
    }

    // --------------------------------------------------------
    // pairing.json
    // --------------------------------------------------------

    std::wstring json =
        ReadTextFile(
            PAIRING_FILE
        );

    if (json.empty())
    {
        InterlockedExchange(
            &_approvalThreadRunning,
            0
        );

        if (_events)
        {
            SetStatusText(
                _events,
                this,
                L"Chyba: pairing.json nebyl nalezen."
            );
        }

        return S_OK;
    }

    std::wstring pairId =
        ExtractJsonString(
            json,
            L"pairId"
        );

    std::wstring pairSecret =
        ExtractJsonString(
            json,
            L"pairSecret"
        );

    std::wstring deviceName =
        ExtractJsonString(
            json,
            L"deviceName"
        );

    if (
        pairId.empty() ||
        pairSecret.empty() ||
        deviceName.empty()
        )
    {
        InterlockedExchange(
            &_approvalThreadRunning,
            0
        );

        if (_events)
        {
            SetStatusText(
                _events,
                this,
                L"Chyba: pairing.json je neplatny."
            );
        }

        return S_OK;
    }

    // --------------------------------------------------------
    // Challenge
    // --------------------------------------------------------

    std::wstring challenge =
        CreateChallenge();

    if (challenge.empty())
    {
        InterlockedExchange(
            &_approvalThreadRunning,
            0
        );

        if (_events)
        {
            SetStatusText(
                _events,
                this,
                L"Chyba: nepodarilo se vytvorit challenge."
            );
        }

        return S_OK;
    }

    // --------------------------------------------------------
    // JSON
    // --------------------------------------------------------

    std::wstring body =
        L"{"
        L"\"deviceName\":\"" +
        deviceName +
        L"\","
        L"\"pairId\":\"" +
        pairId +
        L"\","
        L"\"pairSecret\":\"" +
        pairSecret +
        L"\","
        L"\"challenge\":\"" +
        challenge +
        L"\""
        L"}";

    int bodySize =
        WideCharToMultiByte(
            CP_UTF8,
            0,
            body.c_str(),
            static_cast<int>(
                body.length()
                ),
            nullptr,
            0,
            nullptr,
            nullptr
        );

    if (bodySize <= 0)
    {
        InterlockedExchange(
            &_approvalThreadRunning,
            0
        );

        if (_events)
        {
            SetStatusText(
                _events,
                this,
                L"Chyba pri priprave pozadavku."
            );
        }

        return S_OK;
    }

    std::string bodyUtf8(
        bodySize,
        '\0'
    );

    WideCharToMultiByte(
        CP_UTF8,
        0,
        body.c_str(),
        static_cast<int>(
            body.length()
            ),
        bodyUtf8.data(),
        bodySize,
        nullptr,
        nullptr
    );

    // --------------------------------------------------------
    // WinHTTP
    // --------------------------------------------------------

    HINTERNET session =
        WinHttpOpen(
            L"PhoneUnlockCredentialProvider/1.0",
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );

    if (!session)
    {
        InterlockedExchange(
            &_approvalThreadRunning,
            0
        );

        if (_events)
        {
            SetStatusText(
                _events,
                this,
                L"Chyba: nelze otevrit WinHTTP."
            );
        }

        return S_OK;
    }

    WinHttpSetTimeouts(
        session,
        3000,
        3000,
        3000,
        3000
    );

    HINTERNET connection =
        WinHttpConnect(
            session,
            SERVER_HOST,
            SERVER_PORT,
            0
        );

    if (!connection)
    {
        WinHttpCloseHandle(
            session
        );

        InterlockedExchange(
            &_approvalThreadRunning,
            0
        );

        if (_events)
        {
            SetStatusText(
                _events,
                this,
                L"Chyba: server neni dostupny."
            );
        }

        return S_OK;
    }

    HINTERNET request =
        WinHttpOpenRequest(
            connection,
            L"POST",
            L"/auth/request",
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE
        );

    if (!request)
    {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);

        InterlockedExchange(
            &_approvalThreadRunning,
            0
        );

        if (_events)
        {
            SetStatusText(
                _events,
                this,
                L"Chyba: nelze vytvorit HTTP request."
            );
        }

        return S_OK;
    }

    ConfigureSecureRequest(
        request
    );

    const wchar_t* headers =
        L"Content-Type: application/json\r\n";

    BOOL sent =
        WinHttpSendRequest(
            request,
            headers,
            static_cast<DWORD>(-1L),
            bodyUtf8.data(),
            static_cast<DWORD>(
                bodyUtf8.size()
                ),
            static_cast<DWORD>(
                bodyUtf8.size()
                ),
            0
        );

    BOOL received = FALSE;

    if (sent)
    {
        received =
            WinHttpReceiveResponse(
                request,
                nullptr
            );
    }

    std::wstring responseBody;

    if (sent && received)
    {
        DWORD available = 0;

        while (
            WinHttpQueryDataAvailable(
                request,
                &available
            ) &&
            available > 0
            )
        {
            std::string buffer(
                available,
                '\0'
            );

            DWORD bytesRead = 0;

            if (
                !WinHttpReadData(
                    request,
                    buffer.data(),
                    available,
                    &bytesRead
                )
                )
            {
                break;
            }

            if (bytesRead == 0)
                break;

            int wideLength =
                MultiByteToWideChar(
                    CP_UTF8,
                    0,
                    buffer.data(),
                    bytesRead,
                    nullptr,
                    0
                );

            if (wideLength > 0)
            {
                std::wstring wide(
                    wideLength,
                    L'\0'
                );

                MultiByteToWideChar(
                    CP_UTF8,
                    0,
                    buffer.data(),
                    bytesRead,
                    wide.data(),
                    wideLength
                );

                responseBody +=
                    wide;
            }
        }
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);

    if (
        !sent ||
        !received
        )
    {
        InterlockedExchange(
            &_approvalThreadRunning,
            0
        );

        if (_events)
        {
            SetStatusText(
                _events,
                this,
                L"Pozadavek se nepodarilo odeslat."
            );
        }

        return S_OK;
    }

    // --------------------------------------------------------
    // requestId
    // --------------------------------------------------------

    std::wstring requestId =
        ExtractJsonString(
            responseBody,
            L"requestId"
        );

    if (requestId.empty())
    {
        InterlockedExchange(
            &_approvalThreadRunning,
            0
        );

        if (_events)
        {
            SetStatusText(
                _events,
                this,
                L"Server nevratil requestId."
            );
        }

        return S_OK;
    }

    _requestId =
        requestId;

    _pairSecret =
        pairSecret;

    if (_events)
    {
        SetStatusText(
            _events,
            this,
            L"Pozadavek odeslan. Schval prihlaseni na telefonu."
        );
    }

    // --------------------------------------------------------
    // Start approval worker
    // --------------------------------------------------------

    _approvalThread =
        CreateThread(
            nullptr,
            0,
            ApprovalThreadProc,
            this,
            0,
            nullptr
        );

    if (!_approvalThread)
    {
        InterlockedExchange(
            &_approvalThreadRunning,
            0
        );

        if (_events)
        {
            SetStatusText(
                _events,
                this,
                L"Chyba: nepodarilo se spustit kontrolu."
            );
        }

        return S_OK;
    }

    CloseHandle(
        _approvalThread
    );

    _approvalThread =
        nullptr;

    return S_OK;
}


// ============================================================
// GetSerialization
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
    if (
        !pcpgsr ||
        !pcpcs ||
        !ppwszOptionalStatusText ||
        !pcpsiOptionalStatusIcon
        )
    {
        return E_POINTER;
    }

    *pcpgsr =
        CPGSR_NO_CREDENTIAL_NOT_FINISHED;

    ZeroMemory(
        pcpcs,
        sizeof(*pcpcs)
    );

    *ppwszOptionalStatusText =
        nullptr;

    *pcpsiOptionalStatusIcon =
        CPSI_NONE;

    // --------------------------------------------------------
    // Phone approval required
    // --------------------------------------------------------

    if (
        InterlockedCompareExchange(
            &_approved,
            0,
            0
        ) == 0
        )
    {
        const wchar_t* message =
            L"Nejprve schval prihlaseni telefonem.";

        size_t length =
            wcslen(message) + 1;

        *ppwszOptionalStatusText =
            static_cast<PWSTR>(
                CoTaskMemAlloc(
                    length *
                    sizeof(wchar_t)
                )
                );

        if (*ppwszOptionalStatusText)
        {
            memcpy(
                *ppwszOptionalStatusText,
                message,
                length *
                sizeof(wchar_t)
            );
        }

        return S_OK;
    }

    // --------------------------------------------------------
    // Validate username
    // --------------------------------------------------------

    if (_username.empty())
    {
        const wchar_t* message =
            L"Zadej uzivatelske jmeno.";

        size_t length =
            wcslen(message) + 1;

        *ppwszOptionalStatusText =
            static_cast<PWSTR>(
                CoTaskMemAlloc(
                    length *
                    sizeof(wchar_t)
                )
                );

        if (*ppwszOptionalStatusText)
        {
            memcpy(
                *ppwszOptionalStatusText,
                message,
                length *
                sizeof(wchar_t)
            );
        }

        return S_OK;
    }

    // --------------------------------------------------------
    // Validate password
    // --------------------------------------------------------

    if (_password.empty())
    {
        const wchar_t* message =
            L"Zadej heslo.";

        size_t length =
            wcslen(message) + 1;

        *ppwszOptionalStatusText =
            static_cast<PWSTR>(
                CoTaskMemAlloc(
                    length *
                    sizeof(wchar_t)
                )
                );

        if (*ppwszOptionalStatusText)
        {
            memcpy(
                *ppwszOptionalStatusText,
                message,
                length *
                sizeof(wchar_t)
            );
        }

        return S_OK;
    }

    // --------------------------------------------------------
    // Computer name
    // --------------------------------------------------------

    wchar_t computerName[
        MAX_COMPUTERNAME_LENGTH + 1
    ];

    DWORD computerNameSize =
        ARRAYSIZE(
            computerName
        );

    if (
        !GetComputerNameW(
            computerName,
            &computerNameSize
        )
        )
    {
        return HRESULT_FROM_WIN32(
            GetLastError()
        );
    }

    // --------------------------------------------------------
    // Split qualified username
    //
    // Examples:
    //
    // LAPTOP-K5P8L5CG\petma
    //
    // becomes:
    //
    // domain   = LAPTOP-K5P8L5CG
    // username = petma
    // --------------------------------------------------------

    std::wstring domain;
    std::wstring username;

    size_t slash =
        _username.find(
            L'\\'
        );

    if (slash != std::wstring::npos)
    {
        domain =
            _username.substr(
                0,
                slash
            );

        username =
            _username.substr(
                slash + 1
            );
    }
    else
    {
        domain =
            computerName;

        username =
            _username;
    }

    if (
        domain.empty() ||
        username.empty()
        )
    {
        return E_INVALIDARG;
    }

    // --------------------------------------------------------
    // Protect password
    // --------------------------------------------------------

    PWSTR protectedPassword =
        nullptr;

    HRESULT hr =
        ProtectIfNecessaryAndCopyPassword(
            _password.c_str(),
            _cpus,
            &protectedPassword
        );

    if (FAILED(hr))
        return hr;

    // --------------------------------------------------------
    // Initialize KERB_INTERACTIVE_UNLOCK_LOGON
    // --------------------------------------------------------

    KERB_INTERACTIVE_UNLOCK_LOGON kiul;

    ZeroMemory(
        &kiul,
        sizeof(kiul)
    );

    hr =
        KerbInteractiveUnlockLogonInit(
            const_cast<PWSTR>(
                domain.c_str()
                ),
            const_cast<PWSTR>(
                username.c_str()
                ),
            protectedPassword,
            _cpus,
            &kiul
        );

    if (SUCCEEDED(hr))
    {
        hr =
            KerbInteractiveUnlockLogonPack(
                kiul,
                &pcpcs->rgbSerialization,
                &pcpcs->cbSerialization
            );
    }

    // --------------------------------------------------------
    // Clear protected password
    // --------------------------------------------------------

    if (protectedPassword)
    {
        SecureZeroMemory(
            protectedPassword,
            wcslen(protectedPassword) *
            sizeof(wchar_t)
        );

        CoTaskMemFree(
            protectedPassword
        );

        protectedPassword =
            nullptr;
    }

    // --------------------------------------------------------
    // Clear local password
    // --------------------------------------------------------

    if (!_password.empty())
    {
        SecureZeroMemory(
            _password.data(),
            _password.size() *
            sizeof(wchar_t)
        );

        _password.clear();
    }

    if (FAILED(hr))
    {
        if (pcpcs->rgbSerialization)
        {
            CoTaskMemFree(
                pcpcs->rgbSerialization
            );

            pcpcs->rgbSerialization =
                nullptr;

            pcpcs->cbSerialization =
                0;
        }

        return hr;
    }

    // --------------------------------------------------------
    // Negotiate authentication package
    // --------------------------------------------------------

    ULONG authPackage = 0;

    hr =
        RetrieveNegotiateAuthPackage(
            &authPackage
        );

    if (FAILED(hr))
    {
        CoTaskMemFree(
            pcpcs->rgbSerialization
        );

        pcpcs->rgbSerialization =
            nullptr;

        pcpcs->cbSerialization =
            0;

        return hr;
    }

    pcpcs->ulAuthenticationPackage =
        authPackage;

    pcpcs->clsidCredentialProvider =
        CLSID_PhoneUnlockProvider;

    // --------------------------------------------------------
    // Credential finished
    // --------------------------------------------------------

    *pcpgsr =
        CPGSR_RETURN_CREDENTIAL_FINISHED;

    return S_OK;
}


// ============================================================
// ReportResult
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockCredential::ReportResult(
    NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
    if (
        !ppwszOptionalStatusText ||
        !pcpsiOptionalStatusIcon
        )
    {
        return E_POINTER;
    }

    *ppwszOptionalStatusText =
        nullptr;

    *pcpsiOptionalStatusIcon =
        CPSI_ERROR;

    wchar_t message[256];

    swprintf_s(
        message,
        ARRAYSIZE(message),
        L"Windows prihlaseni selhalo. Status: 0x%08X, SubStatus: 0x%08X",
        static_cast<unsigned int>(
            ntsStatus
            ),
        static_cast<unsigned int>(
            ntsSubstatus
            )
    );

    size_t length =
        wcslen(message) + 1;

    *ppwszOptionalStatusText =
        static_cast<PWSTR>(
            CoTaskMemAlloc(
                length *
                sizeof(wchar_t)
            )
            );

    if (!*ppwszOptionalStatusText)
        return E_OUTOFMEMORY;

    memcpy(
        *ppwszOptionalStatusText,
        message,
        length *
        sizeof(wchar_t)
    );

    // Clear the password after an authentication attempt.
    if (!_password.empty())
    {
        SecureZeroMemory(
            _password.data(),
            _password.size() *
            sizeof(wchar_t)
        );

        _password.clear();
    }

    return S_OK;
}