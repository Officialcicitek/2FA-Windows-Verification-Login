#pragma once

#include <windows.h>
#include <credentialprovider.h>
#include <string>

#define FIELD_TITLE     0
#define FIELD_USERNAME  1
#define FIELD_PASSWORD  2
#define FIELD_STATUS    3
#define FIELD_BUTTON    4
#define FIELD_COUNT     5


class PhoneUnlockCredential :
    public ICredentialProviderCredential
{
private:

    LONG _refCount;

    ICredentialProviderCredentialEvents* _events;

    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;

    HANDLE _approvalThread;

    volatile LONG _approvalThreadRunning;

    volatile LONG _approved;

    std::wstring _requestId;

    std::wstring _pairSecret;

    std::wstring _username;

    std::wstring _password;


    static DWORD WINAPI ApprovalThreadProc(
        LPVOID parameter
    );


public:

    explicit PhoneUnlockCredential(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus
    );

    ~PhoneUnlockCredential();


    HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid,
        void** ppvObject
    ) override;

    ULONG STDMETHODCALLTYPE AddRef() override;

    ULONG STDMETHODCALLTYPE Release() override;


    HRESULT STDMETHODCALLTYPE Advise(
        ICredentialProviderCredentialEvents* pcpce
    ) override;

    HRESULT STDMETHODCALLTYPE UnAdvise() override;

    HRESULT STDMETHODCALLTYPE SetSelected(
        BOOL* pbAutoLogon
    ) override;

    HRESULT STDMETHODCALLTYPE SetDeselected() override;


    HRESULT STDMETHODCALLTYPE GetFieldState(
        DWORD dwFieldID,
        CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
    ) override;


    HRESULT STDMETHODCALLTYPE GetStringValue(
        DWORD dwFieldID,
        PWSTR* ppwsz
    ) override;


    HRESULT STDMETHODCALLTYPE GetBitmapValue(
        DWORD dwFieldID,
        HBITMAP* phbmp
    ) override;


    HRESULT STDMETHODCALLTYPE GetCheckboxValue(
        DWORD dwFieldID,
        BOOL* pbChecked,
        PWSTR* ppwszLabel
    ) override;


    HRESULT STDMETHODCALLTYPE GetSubmitButtonValue(
        DWORD dwFieldID,
        DWORD* pdwAdjacentTo
    ) override;


    HRESULT STDMETHODCALLTYPE GetComboBoxValueCount(
        DWORD dwFieldID,
        DWORD* pcItems,
        DWORD* pdwSelectedItem
    ) override;


    HRESULT STDMETHODCALLTYPE GetComboBoxValueAt(
        DWORD dwFieldID,
        DWORD dwItem,
        PWSTR* ppwszItem
    ) override;


    HRESULT STDMETHODCALLTYPE SetStringValue(
        DWORD dwFieldID,
        PCWSTR pwz
    ) override;


    HRESULT STDMETHODCALLTYPE SetCheckboxValue(
        DWORD dwFieldID,
        BOOL bChecked
    ) override;


    HRESULT STDMETHODCALLTYPE SetComboBoxSelectedValue(
        DWORD dwFieldID,
        DWORD dwSelectedItem
    ) override;


    HRESULT STDMETHODCALLTYPE CommandLinkClicked(
        DWORD dwFieldID
    ) override;


    HRESULT STDMETHODCALLTYPE GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    ) override;


    HRESULT STDMETHODCALLTYPE ReportResult(
        NTSTATUS ntsStatus,
        NTSTATUS ntsSubstatus,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    ) override;
};