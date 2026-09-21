#include "PhoneUnlockProvider.h"
#include "PhoneUnlockCredential.h"

#include <new>
#include <cwchar>
#include <cstring>

PhoneUnlockProvider::PhoneUnlockProvider()
    :
    _refCount(1),
    _events(nullptr),
    _cpus(CPUS_INVALID)
{
    InterlockedIncrement(
        &g_dllObjectCount
    );
}

PhoneUnlockProvider::~PhoneUnlockProvider()
{
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
PhoneUnlockProvider::QueryInterface(
    REFIID riid,
    void** ppvObject
)
{
    if (!ppvObject)
        return E_POINTER;

    *ppvObject = nullptr;

    if (
        riid == IID_IUnknown ||
        riid == IID_ICredentialProvider
        )
    {
        *ppvObject =
            static_cast<ICredentialProvider*>(this);

        AddRef();

        return S_OK;
    }

    return E_NOINTERFACE;
}


ULONG STDMETHODCALLTYPE
PhoneUnlockProvider::AddRef()
{
    return InterlockedIncrement(
        &_refCount
    );
}


ULONG STDMETHODCALLTYPE
PhoneUnlockProvider::Release()
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
// Usage scenario
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD
)
{
    if (
        cpus != CPUS_LOGON &&
        cpus != CPUS_UNLOCK_WORKSTATION
        )
    {
        return E_NOTIMPL;
    }

    _cpus = cpus;

    return S_OK;
}


// ============================================================
// SetSerialization
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockProvider::SetSerialization(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*
)
{
    return E_NOTIMPL;
}


// ============================================================
// Advise
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockProvider::Advise(
    ICredentialProviderEvents* pcpe,
    UINT_PTR
)
{
    if (_events)
    {
        _events->Release();
        _events = nullptr;
    }

    if (pcpe)
    {
        _events = pcpe;
        _events->AddRef();
    }

    return S_OK;
}


// ============================================================
// UnAdvise
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockProvider::UnAdvise()
{
    if (_events)
    {
        _events->Release();
        _events = nullptr;
    }

    return S_OK;
}


// ============================================================
// Field descriptor count
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockProvider::GetFieldDescriptorCount(
    DWORD* pdwCount
)
{
    if (!pdwCount)
        return E_POINTER;

    *pdwCount = FIELD_COUNT;

    return S_OK;
}


// ============================================================
// Field descriptor
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
)
{
    if (!ppcpfd)
        return E_POINTER;

    *ppcpfd = nullptr;

    if (dwIndex >= FIELD_COUNT)
        return E_INVALIDARG;


    auto* descriptor =
        static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
            CoTaskMemAlloc(
                sizeof(
                    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR
                    )
            )
            );

    if (!descriptor)
        return E_OUTOFMEMORY;


    ZeroMemory(
        descriptor,
        sizeof(
            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR
            )
    );


    descriptor->dwFieldID =
        dwIndex;

    descriptor->guidFieldType =
        GUID_NULL;


    const wchar_t* label = nullptr;


    switch (dwIndex)
    {
    case FIELD_TITLE:

        descriptor->cpft =
            CPFT_LARGE_TEXT;

        label =
            L"PhoneUnlock";

        break;


    case FIELD_USERNAME:

        descriptor->cpft =
            CPFT_EDIT_TEXT;

        label =
            L"Uživatelské jméno";

        break;


    case FIELD_PASSWORD:

        descriptor->cpft =
            CPFT_PASSWORD_TEXT;

        label =
            L"Heslo";

        break;


    case FIELD_STATUS:

        descriptor->cpft =
            CPFT_SMALL_TEXT;

        label =
            L"Status";

        break;


    case FIELD_BUTTON:

        descriptor->cpft =
            CPFT_COMMAND_LINK;

        label =
            L"Schválit přihlášení telefonem";

        break;


    default:

        CoTaskMemFree(
            descriptor
        );

        return E_INVALIDARG;
    }


    size_t length =
        wcslen(label) + 1;


    descriptor->pszLabel =
        static_cast<PWSTR>(
            CoTaskMemAlloc(
                length *
                sizeof(wchar_t)
            )
            );


    if (!descriptor->pszLabel)
    {
        CoTaskMemFree(
            descriptor
        );

        return E_OUTOFMEMORY;
    }


    memcpy(
        descriptor->pszLabel,
        label,
        length *
        sizeof(wchar_t)
    );


    *ppcpfd =
        descriptor;

    return S_OK;
}


// ============================================================
// Credential count
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockProvider::GetCredentialCount(
    DWORD* pdwCount,
    DWORD* pdwDefault,
    BOOL* pbAutoLogonWithDefault
)
{
    if (
        !pdwCount ||
        !pdwDefault ||
        !pbAutoLogonWithDefault
        )
    {
        return E_POINTER;
    }


    *pdwCount = 1;

    *pdwDefault = 0;

    *pbAutoLogonWithDefault =
        FALSE;


    return S_OK;
}


// ============================================================
// Credential
// ============================================================

HRESULT STDMETHODCALLTYPE
PhoneUnlockProvider::GetCredentialAt(
    DWORD dwIndex,
    ICredentialProviderCredential** ppcpc
)
{
    if (!ppcpc)
        return E_POINTER;

    *ppcpc = nullptr;


    if (dwIndex != 0)
        return E_INVALIDARG;


    if (
        _cpus != CPUS_LOGON &&
        _cpus != CPUS_UNLOCK_WORKSTATION
        )
    {
        return E_NOTIMPL;
    }


    PhoneUnlockCredential* credential =
        new (std::nothrow)
        PhoneUnlockCredential(
            _cpus
        );


    if (!credential)
        return E_OUTOFMEMORY;


    *ppcpc =
        credential;


    return S_OK;
}