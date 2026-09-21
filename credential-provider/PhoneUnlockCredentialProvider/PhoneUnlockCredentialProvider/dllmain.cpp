#include <windows.h>
#include <credentialprovider.h>
#include <new>

#include "PhoneUnlockProvider.h"


// ============================================================
// PhoneUnlock Credential Provider CLSID
// ============================================================

const GUID CLSID_PhoneUnlockProvider =
{
    0x7c6a5e31,
    0x9b42,
    0x4e18,
    {
        0x91,
        0x7a,
        0x2d,
        0x8f,
        0x44,
        0x63,
        0xb1,
        0x09
    }
};


// ============================================================
// DLL lifetime tracking
// ============================================================

LONG g_dllObjectCount = 0;
LONG g_dllServerLockCount = 0;


// ============================================================
// Class Factory
// ============================================================

class PhoneUnlockClassFactory : public IClassFactory
{
private:
    LONG _refCount;

public:

    PhoneUnlockClassFactory()
        : _refCount(1)
    {
        InterlockedIncrement(&g_dllObjectCount);
    }


    ~PhoneUnlockClassFactory()
    {
        InterlockedDecrement(&g_dllObjectCount);
    }


    // --------------------------------------------------------
    // IUnknown
    // --------------------------------------------------------

    HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid,
        void** ppvObject
    ) override
    {
        if (!ppvObject)
            return E_POINTER;

        *ppvObject = nullptr;

        if (
            riid == IID_IUnknown ||
            riid == IID_IClassFactory
            )
        {
            *ppvObject =
                static_cast<IClassFactory*>(this);

            AddRef();

            return S_OK;
        }

        return E_NOINTERFACE;
    }


    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return InterlockedIncrement(&_refCount);
    }


    ULONG STDMETHODCALLTYPE Release() override
    {
        LONG refCount =
            InterlockedDecrement(&_refCount);

        if (refCount == 0)
        {
            delete this;
        }

        return refCount;
    }


    // --------------------------------------------------------
    // IClassFactory
    // --------------------------------------------------------

    HRESULT STDMETHODCALLTYPE CreateInstance(
        IUnknown* pUnkOuter,
        REFIID riid,
        void** ppvObject
    ) override
    {
        if (!ppvObject)
            return E_POINTER;

        *ppvObject = nullptr;


        // Aggregation is not supported
        if (pUnkOuter)
            return CLASS_E_NOAGGREGATION;


        PhoneUnlockProvider* provider =
            new (std::nothrow) PhoneUnlockProvider();

        if (!provider)
            return E_OUTOFMEMORY;


        HRESULT hr =
            provider->QueryInterface(
                riid,
                ppvObject
            );


        provider->Release();


        return hr;
    }


    HRESULT STDMETHODCALLTYPE LockServer(
        BOOL fLock
    ) override
    {
        if (fLock)
        {
            InterlockedIncrement(
                &g_dllServerLockCount
            );
        }
        else
        {
            InterlockedDecrement(
                &g_dllServerLockCount
            );
        }

        return S_OK;
    }
};


// ============================================================
// DllGetClassObject
// ============================================================

extern "C" HRESULT WINAPI DllGetClassObject(
    REFCLSID rclsid,
    REFIID riid,
    LPVOID* ppv
)
{
    if (!ppv)
        return E_POINTER;

    *ppv = nullptr;


    // Check CLSID

    if (rclsid != CLSID_PhoneUnlockProvider)
    {
        return CLASS_E_CLASSNOTAVAILABLE;
    }


    // Create class factory

    PhoneUnlockClassFactory* factory =
        new (std::nothrow) PhoneUnlockClassFactory();

    if (!factory)
        return E_OUTOFMEMORY;


    HRESULT hr =
        factory->QueryInterface(
            riid,
            ppv
        );


    factory->Release();


    return hr;
}


// ============================================================
// DllCanUnloadNow
// ============================================================

extern "C" HRESULT WINAPI DllCanUnloadNow()
{
    if (
        g_dllObjectCount == 0 &&
        g_dllServerLockCount == 0
        )
    {
        return S_OK;
    }

    return S_FALSE;
}


// ============================================================
// DllMain
// ============================================================

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
)
{
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        DisableThreadLibraryCalls(hModule);

        break;


    case DLL_PROCESS_DETACH:

        break;
    }

    return TRUE;
}