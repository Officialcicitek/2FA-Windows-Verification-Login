#include "helpers.h"

#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <wincred.h>

#include <intsafe.h>
#include <shlwapi.h>
#include <strsafe.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "secur32.lib")

#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#include <ntstatus.h>
#undef WIN32_NO_STATUS
#else
#include <ntstatus.h>
#endif

#ifndef NEGOSSP_NAME_A
#define NEGOSSP_NAME_A "Negotiate"
#endif


// ============================================================
// UnicodeStringInitWithString
// ============================================================

HRESULT UnicodeStringInitWithString(
    PWSTR pwz,
    UNICODE_STRING* pus
)
{
    if (!pwz || !pus)
        return E_INVALIDARG;

    size_t lenString =
        wcslen(pwz);

    USHORT usCharCount = 0;

    HRESULT hr =
        SizeTToUShort(
            lenString,
            &usCharCount
        );

    if (FAILED(hr))
        return hr;

    USHORT usSize =
        sizeof(WCHAR);

    hr =
        UShortMult(
            usCharCount,
            usSize,
            &pus->Length
        );

    if (FAILED(hr))
    {
        return HRESULT_FROM_WIN32(
            ERROR_ARITHMETIC_OVERFLOW
        );
    }

    pus->MaximumLength =
        pus->Length;

    pus->Buffer =
        pwz;

    return S_OK;
}


// ============================================================
// UnicodeStringPackedUnicodeStringCopy
// ============================================================

static void UnicodeStringPackedUnicodeStringCopy(
    const UNICODE_STRING& source,
    PWSTR destination,
    UNICODE_STRING* output
)
{
    output->Length =
        source.Length;

    output->MaximumLength =
        source.Length;

    output->Buffer =
        destination;

    if (
        source.Length > 0 &&
        source.Buffer
        )
    {
        CopyMemory(
            output->Buffer,
            source.Buffer,
            source.Length
        );
    }
}


// ============================================================
// KerbInteractiveUnlockLogonInit
// ============================================================

HRESULT KerbInteractiveUnlockLogonInit(
    PWSTR pwzDomain,
    PWSTR pwzUsername,
    PWSTR pwzPassword,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    KERB_INTERACTIVE_UNLOCK_LOGON* pkiul
)
{
    if (!pkiul)
        return E_POINTER;

    if (
        !pwzDomain ||
        !pwzUsername ||
        !pwzPassword
        )
    {
        return E_INVALIDARG;
    }

    KERB_INTERACTIVE_UNLOCK_LOGON kiul;

    ZeroMemory(
        &kiul,
        sizeof(kiul)
    );

    KERB_INTERACTIVE_LOGON* pkil =
        &kiul.Logon;

    // --------------------------------------------------------
    // Domain
    // --------------------------------------------------------

    HRESULT hr =
        UnicodeStringInitWithString(
            pwzDomain,
            &pkil->LogonDomainName
        );

    // --------------------------------------------------------
    // Username
    // --------------------------------------------------------

    if (SUCCEEDED(hr))
    {
        hr =
            UnicodeStringInitWithString(
                pwzUsername,
                &pkil->UserName
            );
    }

    // --------------------------------------------------------
    // Password
    // --------------------------------------------------------

    if (SUCCEEDED(hr))
    {
        hr =
            UnicodeStringInitWithString(
                pwzPassword,
                &pkil->Password
            );
    }

    if (FAILED(hr))
        return hr;

    // --------------------------------------------------------
    // Message type
    // --------------------------------------------------------

    switch (cpus)
    {
    case CPUS_UNLOCK_WORKSTATION:

        pkil->MessageType =
            KerbWorkstationUnlockLogon;

        hr =
            S_OK;

        break;

    case CPUS_LOGON:

        pkil->MessageType =
            KerbInteractiveLogon;

        hr =
            S_OK;

        break;

    case CPUS_CREDUI:

        pkil->MessageType =
            static_cast<KERB_LOGON_SUBMIT_TYPE>(0);

        hr =
            S_OK;

        break;

    default:

        hr =
            E_NOTIMPL;

        break;
    }

    if (SUCCEEDED(hr))
    {
        CopyMemory(
            pkiul,
            &kiul,
            sizeof(*pkiul)
        );
    }

    return hr;
}


// ============================================================
// KerbInteractiveUnlockLogonPack
// ============================================================

HRESULT KerbInteractiveUnlockLogonPack(
    const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
    BYTE** prgb,
    DWORD* pcb
)
{
    if (
        !prgb ||
        !pcb
        )
    {
        return E_POINTER;
    }

    *prgb =
        nullptr;

    *pcb =
        0;

    const KERB_INTERACTIVE_LOGON* pkilIn =
        &rkiulIn.Logon;

    // --------------------------------------------------------
    // Structure + domain + username + password
    // --------------------------------------------------------

    ULONGLONG totalSize =
        static_cast<ULONGLONG>(
            sizeof(rkiulIn)
            ) +
        pkilIn->LogonDomainName.Length +
        pkilIn->UserName.Length +
        pkilIn->Password.Length;

    if (totalSize > MAXDWORD)
    {
        return HRESULT_FROM_WIN32(
            ERROR_ARITHMETIC_OVERFLOW
        );
    }

    DWORD cb =
        static_cast<DWORD>(
            totalSize
            );

    // --------------------------------------------------------
    // Allocate packed structure
    // --------------------------------------------------------

    KERB_INTERACTIVE_UNLOCK_LOGON* pkiulOut =
        static_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(
            CoTaskMemAlloc(
                cb
            )
            );

    if (!pkiulOut)
        return E_OUTOFMEMORY;

    ZeroMemory(
        pkiulOut,
        cb
    );

    // --------------------------------------------------------
    // Buffer starts directly after structure
    // --------------------------------------------------------

    BYTE* pbBuffer =
        reinterpret_cast<BYTE*>(
            pkiulOut
            ) +
        sizeof(*pkiulOut);

    KERB_INTERACTIVE_LOGON* pkilOut =
        &pkiulOut->Logon;

    pkilOut->MessageType =
        pkilIn->MessageType;

    // --------------------------------------------------------
    // Domain
    // --------------------------------------------------------

    UnicodeStringPackedUnicodeStringCopy(
        pkilIn->LogonDomainName,
        reinterpret_cast<PWSTR>(
            pbBuffer
            ),
        &pkilOut->LogonDomainName
    );

    pkilOut->LogonDomainName.Buffer =
        reinterpret_cast<PWSTR>(
            pbBuffer -
            reinterpret_cast<BYTE*>(
                pkiulOut
                )
            );

    pbBuffer +=
        pkilOut->LogonDomainName.Length;

    // --------------------------------------------------------
    // Username
    // --------------------------------------------------------

    UnicodeStringPackedUnicodeStringCopy(
        pkilIn->UserName,
        reinterpret_cast<PWSTR>(
            pbBuffer
            ),
        &pkilOut->UserName
    );

    pkilOut->UserName.Buffer =
        reinterpret_cast<PWSTR>(
            pbBuffer -
            reinterpret_cast<BYTE*>(
                pkiulOut
                )
            );

    pbBuffer +=
        pkilOut->UserName.Length;

    // --------------------------------------------------------
    // Password
    // --------------------------------------------------------

    UnicodeStringPackedUnicodeStringCopy(
        pkilIn->Password,
        reinterpret_cast<PWSTR>(
            pbBuffer
            ),
        &pkilOut->Password
    );

    pkilOut->Password.Buffer =
        reinterpret_cast<PWSTR>(
            pbBuffer -
            reinterpret_cast<BYTE*>(
                pkiulOut
                )
            );

    // --------------------------------------------------------
    // Return packed buffer
    // --------------------------------------------------------

    *prgb =
        reinterpret_cast<BYTE*>(
            pkiulOut
            );

    *pcb =
        cb;

    return S_OK;
}


// ============================================================
// LsaInitString
// ============================================================

static HRESULT LsaInitString(
    PLSA_STRING destination,
    PCSTR source
)
{
    if (
        !destination ||
        !source
        )
    {
        return E_INVALIDARG;
    }

    size_t length =
        strlen(source);

    USHORT usLength = 0;

    HRESULT hr =
        SizeTToUShort(
            length,
            &usLength
        );

    if (FAILED(hr))
        return hr;

    destination->Buffer =
        const_cast<PCHAR>(
            source
            );

    destination->Length =
        usLength;

    destination->MaximumLength =
        static_cast<USHORT>(
            usLength + 1
            );

    return S_OK;
}


// ============================================================
// RetrieveNegotiateAuthPackage
// ============================================================

HRESULT RetrieveNegotiateAuthPackage(
    ULONG* pulAuthPackage
)
{
    if (!pulAuthPackage)
        return E_POINTER;

    *pulAuthPackage =
        0;

    HANDLE hLsa =
        nullptr;

    NTSTATUS status =
        LsaConnectUntrusted(
            &hLsa
        );

    // --------------------------------------------------------
    // STATUS_SUCCESS == 0
    // --------------------------------------------------------

    if (status != 0)
    {
        return HRESULT_FROM_NT(
            status
        );
    }

    LSA_STRING packageName;

    HRESULT hr =
        LsaInitString(
            &packageName,
            NEGOSSP_NAME_A
        );

    if (FAILED(hr))
    {
        LsaDeregisterLogonProcess(
            hLsa
        );

        return hr;
    }

    ULONG packageId =
        0;

    status =
        LsaLookupAuthenticationPackage(
            hLsa,
            &packageName,
            &packageId
        );

    LsaDeregisterLogonProcess(
        hLsa
    );

    // --------------------------------------------------------
    // STATUS_SUCCESS == 0
    // --------------------------------------------------------

    if (status != 0)
    {
        return HRESULT_FROM_NT(
            status
        );
    }

    *pulAuthPackage =
        packageId;

    return S_OK;
}


// ============================================================
// _ProtectAndCopyString
// ============================================================

static HRESULT _ProtectAndCopyString(
    PCWSTR pwzToProtect,
    PWSTR* ppwzProtected
)
{
    if (
        !pwzToProtect ||
        !ppwzProtected
        )
    {
        return E_INVALIDARG;
    }

    *ppwzProtected =
        nullptr;

    PWSTR pwzToProtectCopy =
        nullptr;

    HRESULT hr =
        SHStrDupW(
            pwzToProtect,
            &pwzToProtectCopy
        );

    if (FAILED(hr))
        return hr;

    DWORD cchProtected =
        0;

    DWORD cchCredentials =
        static_cast<DWORD>(
            wcslen(
                pwzToProtectCopy
            ) + 1
            );

    // --------------------------------------------------------
    // First call: obtain required size
    // --------------------------------------------------------

    if (
        !CredProtectW(
            FALSE,
            pwzToProtectCopy,
            cchCredentials,
            nullptr,
            &cchProtected,
            nullptr
        )
        )
    {
        DWORD dwErr =
            GetLastError();

        if (
            dwErr !=
            ERROR_INSUFFICIENT_BUFFER ||
            cchProtected == 0
            )
        {
            SecureZeroMemory(
                pwzToProtectCopy,
                wcslen(
                    pwzToProtectCopy
                ) *
                sizeof(WCHAR)
            );

            CoTaskMemFree(
                pwzToProtectCopy
            );

            return HRESULT_FROM_WIN32(
                dwErr
            );
        }
    }

    // --------------------------------------------------------
    // Allocate protected password
    // --------------------------------------------------------

    PWSTR pwzProtected =
        static_cast<PWSTR>(
            CoTaskMemAlloc(
                cchProtected *
                sizeof(WCHAR)
            )
            );

    if (!pwzProtected)
    {
        SecureZeroMemory(
            pwzToProtectCopy,
            wcslen(
                pwzToProtectCopy
            ) *
            sizeof(WCHAR)
        );

        CoTaskMemFree(
            pwzToProtectCopy
        );

        return E_OUTOFMEMORY;
    }

    DWORD cchProtectedBuffer =
        cchProtected;

    // --------------------------------------------------------
    // Second call: actually protect password
    // --------------------------------------------------------

    if (
        !CredProtectW(
            FALSE,
            pwzToProtectCopy,
            cchCredentials,
            pwzProtected,
            &cchProtectedBuffer,
            nullptr
        )
        )
    {
        DWORD dwErr =
            GetLastError();

        SecureZeroMemory(
            pwzProtected,
            cchProtected *
            sizeof(WCHAR)
        );

        CoTaskMemFree(
            pwzProtected
        );

        SecureZeroMemory(
            pwzToProtectCopy,
            wcslen(
                pwzToProtectCopy
            ) *
            sizeof(WCHAR)
        );

        CoTaskMemFree(
            pwzToProtectCopy
        );

        return HRESULT_FROM_WIN32(
            dwErr
        );
    }

    SecureZeroMemory(
        pwzToProtectCopy,
        wcslen(
            pwzToProtectCopy
        ) *
        sizeof(WCHAR)
    );

    CoTaskMemFree(
        pwzToProtectCopy
    );

    *ppwzProtected =
        pwzProtected;

    return S_OK;
}


// ============================================================
// ProtectIfNecessaryAndCopyPassword
// ============================================================

HRESULT ProtectIfNecessaryAndCopyPassword(
    PCWSTR pwzPassword,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    PWSTR* ppwzProtectedPassword
)
{
    if (!ppwzProtectedPassword)
        return E_POINTER;

    *ppwzProtectedPassword =
        nullptr;

    // --------------------------------------------------------
    // Empty password
    // --------------------------------------------------------

    if (
        !pwzPassword ||
        !*pwzPassword
        )
    {
        return SHStrDupW(
            L"",
            ppwzProtectedPassword
        );
    }

    PWSTR pwzPasswordCopy =
        nullptr;

    HRESULT hr =
        SHStrDupW(
            pwzPassword,
            &pwzPasswordCopy
        );

    if (FAILED(hr))
        return hr;

    bool alreadyProtected =
        false;

    CRED_PROTECTION_TYPE protectionType =
        CredUnprotected;

    // --------------------------------------------------------
    // Check if already protected
    // --------------------------------------------------------

    if (
        CredIsProtectedW(
            pwzPasswordCopy,
            &protectionType
        )
        )
    {
        if (
            protectionType !=
            CredUnprotected
            )
        {
            alreadyProtected =
                true;
        }
    }

    // --------------------------------------------------------
    // CPUS_CREDUI or already protected
    // --------------------------------------------------------

    if (
        cpus == CPUS_CREDUI ||
        alreadyProtected
        )
    {
        hr =
            SHStrDupW(
                pwzPasswordCopy,
                ppwzProtectedPassword
            );
    }
    else
    {
        // ----------------------------------------------------
        // CPUS_LOGON / CPUS_UNLOCK_WORKSTATION
        // ----------------------------------------------------

        hr =
            _ProtectAndCopyString(
                pwzPasswordCopy,
                ppwzProtectedPassword
            );
    }

    SecureZeroMemory(
        pwzPasswordCopy,
        wcslen(
            pwzPasswordCopy
        ) *
        sizeof(WCHAR)
    );

    CoTaskMemFree(
        pwzPasswordCopy
    );

    return hr;
}