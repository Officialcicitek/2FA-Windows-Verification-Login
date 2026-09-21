#pragma once

#include <windows.h>
#include <credentialprovider.h>
#include <guiddef.h>

extern const GUID CLSID_PhoneUnlockProvider;

extern LONG g_dllObjectCount;

class PhoneUnlockProvider : public ICredentialProvider
{
private:
    LONG _refCount;

    ICredentialProviderEvents* _events;

    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;

public:
    PhoneUnlockProvider();

    ~PhoneUnlockProvider();

    HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid,
        void** ppvObject
    ) override;

    ULONG STDMETHODCALLTYPE AddRef() override;

    ULONG STDMETHODCALLTYPE Release() override;

    HRESULT STDMETHODCALLTYPE SetUsageScenario(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        DWORD dwFlags
    ) override;

    HRESULT STDMETHODCALLTYPE SetSerialization(
        const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs
    ) override;

    HRESULT STDMETHODCALLTYPE Advise(
        ICredentialProviderEvents* pcpe,
        UINT_PTR upAdviseContext
    ) override;

    HRESULT STDMETHODCALLTYPE UnAdvise() override;

    HRESULT STDMETHODCALLTYPE GetFieldDescriptorCount(
        DWORD* pdwCount
    ) override;

    HRESULT STDMETHODCALLTYPE GetFieldDescriptorAt(
        DWORD dwIndex,
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
    ) override;

    HRESULT STDMETHODCALLTYPE GetCredentialCount(
        DWORD* pdwCount,
        DWORD* pdwDefault,
        BOOL* pbAutoLogonWithDefault
    ) override;

    HRESULT STDMETHODCALLTYPE GetCredentialAt(
        DWORD dwIndex,
        ICredentialProviderCredential** ppcpc
    ) override;
};