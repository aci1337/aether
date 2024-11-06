 
#include <windows.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include <psapi.h>
 
 #define IOCTL_AETHERS_OPEN_PROCESS             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AETHERS_READ_WRITE_MEMORY        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AETHERS_LOCK_UNLOCK_FILE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AETHERS_DELETE_FILE              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

 typedef enum {
    AETHERS_OPEN_PROCESS = 1,
    AETHERS_READ_WRITE_MEMORY,
    AETHERS_LOCK_UNLOCK_FILE,
    AETHERS_DELETE_FILE
} AETHERS_OPERATION_TYPE;

 #pragma pack(push, 1)
typedef struct _AETHERS_OPERATION_REQUEST {
    AETHERS_OPERATION_TYPE operation;
    union {
        struct {
            DWORD pid;  
            ACCESS_MASK access;
        } openProcess;
        struct {
            DWORD pid;  
            PVOID targetAddress;
            PVOID buffer;
            SIZE_T size;
            BOOLEAN isWrite;
        } readWriteMemory;
        struct {
            WCHAR filePath[260];
            BOOLEAN lock;
        } lockUnlockFile;
        struct {
            WCHAR filePath[260];
        } deleteFile;
    } data;
} AETHERS_OPERATION_REQUEST, * PAETHERS_OPERATION_REQUEST;
#pragma pack(pop)

 typedef struct _AETHERS_OPERATION_RESPONSE {
    HANDLE processHandle;
} AETHERS_OPERATION_RESPONSE, * PAETHERS_OPERATION_RESPONSE;
#include <fstream>  

 #define XORSTR_INLINE	__forceinline
#define XORSTR_NOINLINE __declspec( noinline )
#define XORSTR_CONST	constexpr
#define XORSTR_VOLATILE volatile

#define XORSTR_CONST_INLINE \
XORSTR_INLINE XORSTR_CONST 

#define XORSTR_CONST_NOINLINE \
XORSTR_NOINLINE XORSTR_CONST

#define XORSTR_FNV_OFFSET_BASIS 0xCBF29CE484222325
#define XORSTR_FNV_PRIME 0x100000001B3

#define XORSTR_TYPE_SIZEOF( _VALUE ) \
sizeof( decltype( _VALUE ) )

#define XORSTR_BYTE( _VALUE, _IDX )	\
( ( _VALUE >> ( __min( _IDX, ( XORSTR_TYPE_SIZEOF( _VALUE ) ) - 1)  * 8 ) ) & 0xFF )

#define XORSTR_NIBBLE( _VALUE, _IDX ) \
( ( _VALUE >> ( __min( _IDX, ( XORSTR_TYPE_SIZEOF( _VALUE ) * 2 ) - 1 ) * 4 ) ) & 0xF )

#define XORSTR_MAKE_INTEGER_SEQUENCE( _LEN_ ) \
__make_integer_seq< XORSTR_INT_SEQ, SIZE_T, _LEN_ >( )

#define XORSTR_INTEGER_SEQUENCE( _INDICES_ ) \
XORSTR_INT_SEQ< SIZE_T, _INDICES_... >

template< typename _Ty, _Ty... Types >
struct XORSTR_INT_SEQ
{
};


XORSTR_CONST_NOINLINE
INT XORSTR_ATOI8(
    IN CHAR Character
) noexcept
{
    return (Character >= '0' && Character <= '9') ?
        (Character - '0') : NULL;
}

XORSTR_CONST_NOINLINE
UINT64 XORSTR_KEY(
    IN SIZE_T CryptStrLength
) noexcept
{
    UINT64 KeyHash = XORSTR_FNV_OFFSET_BASIS;

    for (SIZE_T i = NULL; i < sizeof(__TIME__); i++) {
        KeyHash = KeyHash ^ (XORSTR_ATOI8(__TIME__[i]) + (CryptStrLength * i)) & 0xFF;
        KeyHash = KeyHash * XORSTR_FNV_PRIME;
    }

    return KeyHash;
}

template< typename _CHAR_TYPE_,
    SIZE_T _STR_LENGTH_ >
class _XORSTR_
{
public:
    XORSTR_CONST_INLINE _XORSTR_(
        IN _CHAR_TYPE_ CONST(&String)[_STR_LENGTH_]
    ) : _XORSTR_(String, XORSTR_MAKE_INTEGER_SEQUENCE(_STR_LENGTH_))
    {
    }

    XORSTR_INLINE
        CONST _CHAR_TYPE_* String(
            VOID
        )
    {
        for (SIZE_T i = NULL; i < _STR_LENGTH_; i++) {
            StringData[i] = CRYPT_CHAR(StringData[i], i);
        }

        return (_CHAR_TYPE_*)(StringData);
    }

private:


    static XORSTR_CONST UINT64 Key = XORSTR_KEY(_STR_LENGTH_);


    static XORSTR_CONST_INLINE
        _CHAR_TYPE_ CRYPT_CHAR(
            IN _CHAR_TYPE_ Character,
            IN SIZE_T KeyIndex
        )
    {
        return (Character ^ ((Key + KeyIndex) ^
            (XORSTR_NIBBLE(Key, KeyIndex % 16))));
    }

    template< SIZE_T... _INDEX_ >
    XORSTR_CONST_INLINE _XORSTR_(
        IN _CHAR_TYPE_ CONST(&String)[_STR_LENGTH_],
        IN XORSTR_INTEGER_SEQUENCE(_INDEX_) IntSeq
    ) : StringData{ CRYPT_CHAR(String[_INDEX_], _INDEX_)... }
    {
    }

    XORSTR_VOLATILE _CHAR_TYPE_ StringData[_STR_LENGTH_];
};

template< SIZE_T _STR_LEN_ >
XORSTR_CONST_INLINE
_XORSTR_< CHAR, _STR_LEN_ > XorStr(
    IN CHAR CONST(&String)[_STR_LEN_]
)
{
    return _XORSTR_< CHAR, _STR_LEN_ >(String);
}


template< SIZE_T _STR_LEN_ >
XORSTR_CONST_INLINE
_XORSTR_< WCHAR, _STR_LEN_ > XorStr(
    IN WCHAR CONST(&String)[_STR_LEN_]
)
{
    return _XORSTR_< WCHAR, _STR_LEN_ >(String);
}


template< SIZE_T _STR_LEN_ >
XORSTR_CONST_INLINE
_XORSTR_< char32_t, _STR_LEN_ > XorStr(
    IN char32_t CONST(&String)[_STR_LEN_]
)
{
    return _XORSTR_< char32_t, _STR_LEN_ >(String);
}

#define xorstr_( _STR_ ) XorStr( _STR_ ).String( )

HANDLE OpenDriverHandle()
{
    HANDLE hDevice = CreateFileW(
        xorstr_(L"\\\\.\\AethersScannerZah"),   
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        wprintf(L"Failed to open driver device. Error: %lu\n", GetLastError());
        return NULL;
    }

    return hDevice;
}

 void CloseDriverHandle(HANDLE hDevice)
{
    if (hDevice != NULL && hDevice != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hDevice);
    }
}

 __forceinline PWCHAR StringCopyW(_Inout_ PWCHAR String1, _In_ LPCWSTR String2)
{
    PWCHAR p = String1;

    while ((*p++ = *String2++) != 0);

    return String1;
}
#include <codecvt>

 __forceinline BOOL SetDebugPrivileges() {
    HANDLE Process = GetCurrentProcess();
    HANDLE Token = INVALID_HANDLE_VALUE;
    TOKEN_PRIVILEGES Privileges = { 0 };
    DWORD TokenLength = 0;
    LUID LocalId = { 0 };
    BOOL bFlag = FALSE;
    WCHAR PrivilegeString[256] = { 0 };

    if (!OpenProcessToken(Process, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &Token))
        return FALSE;

    StringCopyW(PrivilegeString, (PWCHAR)L"SeDebugPrivilege");

    if (LookupPrivilegeValueW(NULL, PrivilegeString, &LocalId)) {
        Privileges.Privileges[0].Luid = LocalId;
        Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        Privileges.PrivilegeCount = 1;

        if (!AdjustTokenPrivileges(Token, FALSE, &Privileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
            CloseHandle(Token);
            return FALSE;
        }
    }

    bFlag = TRUE;
    CloseHandle(Token);
    return bFlag;
}

#include <iomanip> // For std::hex and std::setw

#include <iomanip> // For std::hex and std::setw
#include <map>

class StringCleaner {
public:
    StringCleaner(DWORD processId, std::vector<std::string> strings) {
        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);

        _min_address = (size_t)sys_info.lpMinimumApplicationAddress;
        _max_address = (size_t)sys_info.lpMaximumApplicationAddress;
        _pid = processId;
        _strings = strings;
    }

    void clean(HANDLE processHandle) {
        if (!SetDebugPrivileges()) {
            wprintf(L"Failed to set debug privileges. Some operations may fail.\n");
        }
        _cleanStrings(processHandle);
        CloseHandle(processHandle);
    }

     std::vector<size_t> _find_substr_indexes(const std::string& str, const std::string& substr) {
        std::vector<size_t> indexes;
        if (substr.empty()) return indexes;
        size_t pos = str.find(substr, 0);
        while (pos != std::string::npos) {
            indexes.push_back(pos);
            pos = str.find(substr, pos + 1);
        }
        return indexes;
    }

     std::string extractFullAnsiString(const std::string& buffer, size_t start) {
        size_t end = buffer.find('\0', start);
        if (end == std::string::npos) {
            return buffer.substr(start);
        }
        return buffer.substr(start, end - start);
    }

     std::wstring extractFullWideString(const std::string& buffer, size_t start) {
        std::wstring full_string;
         if (start + 1 >= buffer.size()) return full_string;

        for (size_t i = start; i + 1 < buffer.size(); i += 2) {
            wchar_t wc = buffer[i] | (buffer[i + 1] << 8);
            if (wc == L'\0') break;
            full_string += wc;
        }
        return full_string;
    }

    std::map<std::string, std::vector<size_t>> findStrings(HANDLE processHandle) {
        std::map<std::string, std::vector<size_t>> foundStrings;
        size_t current_address = _min_address;
        MEMORY_BASIC_INFORMATION mbi;
        std::vector<std::string> search_strings;

         for (const std::string& raw_string : _strings) {
            search_strings.push_back(raw_string);

            std::string wide;
            for (const char c : raw_string) {
                wide.push_back(c);
                wide.push_back('\0');  
            }
            search_strings.push_back(wide);
        }

         while (current_address < _max_address) {
            if (VirtualQueryEx(processHandle, (LPCVOID)current_address, &mbi, sizeof(mbi))) {
                 if ((mbi.State & MEM_COMMIT) &&
                    (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {

                    std::vector<BYTE> buffer(mbi.RegionSize);
                    SIZE_T bytesRead = 0;

                     if (ReadProcessMemory(processHandle, (LPCVOID)current_address, buffer.data(), mbi.RegionSize, &bytesRead)) {
                         std::string memContent((char*)buffer.data(), bytesRead);

                        for (const std::string& string_to_find : search_strings) {
                            std::vector<size_t> indexes = _find_substr_indexes(memContent, string_to_find);

                            for (const size_t index : indexes) {
                                size_t found_address = current_address + index;

                                 bool isWide = false;
                                if (string_to_find.size() >= 2) {
                                     isWide = true;
                                    for (size_t i = 1; i < string_to_find.size(); i += 2) {
                                        if (string_to_find[i] != '\0') {
                                            isWide = false;
                                            break;
                                        }
                                    }
                                }

                                 if (isWide) {
                                    std::wstring full_string = extractFullWideString(memContent, index);
                                    if (full_string.size() > 100) {
                                        full_string = full_string.substr(0, 100) + L"...";
                                    }
                                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
                                    wprintf(L"[Aethers] Found full wide string \"%s\" at address: 0x%p\n", full_string.c_str(), (void*)found_address);
                                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                                }
                                else {
                                    std::string full_string = extractFullAnsiString(memContent, index);
                                    if (full_string.size() > 100) {
                                        full_string = full_string.substr(0, 100) + "...";
                                    }
                                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
                                    printf("[Aethers] Found full ANSI string \"%s\" at address: 0x%p\n", full_string.c_str(), (void*)found_address);
                                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                                }

                                 foundStrings[string_to_find].push_back(found_address);
                            }
                        }
                    }
                    else {
                     }
                }
            }
            else {
             }

             current_address += mbi.RegionSize;
        }

        return foundStrings;
    }
private:
    size_t _min_address;
    size_t _max_address;
    std::vector<std::string> _strings;
    DWORD _pid;

     std::vector<size_t> _find_substr_indexes(const std::string& string, const std::string& substring) const {
        std::vector<size_t> indexes;
        size_t index = 0;
        while (true) {
            size_t x = string.find(substring, index);
            if (x == std::string::npos) break;
            indexes.push_back(x);
            index = x + substring.length();
        }
        return indexes;
    }

     void _cleanStrings(HANDLE processHandle) {
        size_t current_address = _min_address;
        MEMORY_BASIC_INFORMATION mbi;
        std::vector<std::string> fixed_strings;

         for (const std::string& raw_string : _strings) {
            fixed_strings.push_back(raw_string);

            std::string wide;
            for (const char c : raw_string) {
                wide.push_back(c);
                wide.push_back(0);
            }
            fixed_strings.push_back(wide);
        }

         while (current_address < _max_address) {
            if (VirtualQueryEx(processHandle, (LPCVOID)current_address, &mbi, sizeof(mbi))) {
                 if ((mbi.State & MEM_COMMIT) &&
                    (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {

                    std::vector<BYTE> buffer(mbi.RegionSize, 0);

                     if (ReadProcessMemory(processHandle, (LPCVOID)current_address, buffer.data(), mbi.RegionSize, nullptr)) {
                        std::string memContent((char*)buffer.data(), mbi.RegionSize);

                        for (const std::string& string_to_remove : fixed_strings) {
                            std::vector<size_t> indexes = _find_substr_indexes(memContent, string_to_remove);

                             std::vector<BYTE> replace(string_to_remove.size(), 0);

                            for (const size_t index : indexes) {
                                 if (WriteProcessMemory(processHandle, (LPVOID)(current_address + index), replace.data(), replace.size(), nullptr)) {
                                    wprintf(L"[Aethers] Cleaned string at address: 0x%p\n", (void*)(current_address + index));
                                }
                                else {
                                    wprintf(L"[Aethers] Failed to clean string at address: 0x%p\n", (void*)(current_address + index));
                                }
                            }
                        }
                    }
                }
            }
            current_address += mbi.RegionSize;
        }
    }
};



 HANDLE AethersOpenProcess(HANDLE hDevice, DWORD pid, ACCESS_MASK access, HANDLE& outProcessHandle)
{
    AETHERS_OPERATION_REQUEST request = { };  
    AETHERS_OPERATION_RESPONSE response = { 0 };
    DWORD bytesReturned = 0;

    request.operation = AETHERS_OPEN_PROCESS;
    request.data.openProcess.pid = pid;  
    request.data.openProcess.access = access;

    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_AETHERS_OPEN_PROCESS,
        &request,
        sizeof(AETHERS_OPERATION_REQUEST),
        &response,
        sizeof(AETHERS_OPERATION_RESPONSE),
        &bytesReturned,
        NULL
    );

    if (!success)
    {
        wprintf(L"AethersOpenProcess failed. Error: %lu\n", GetLastError());
     }

    if (response.processHandle != NULL && response.processHandle != INVALID_HANDLE_VALUE)
    {
        outProcessHandle = response.processHandle;
 
     }
    else
    {
        wprintf(L"AethersOpenProcess returned NULL or INVALID handle.\n");
     }
    return response.processHandle;

}

 bool AethersReadMemory(HANDLE hDevice, DWORD pid, LPCVOID targetAddress, PVOID buffer, SIZE_T size)
{
    AETHERS_OPERATION_REQUEST request = { };  
    AETHERS_OPERATION_RESPONSE response = { 0 };
    DWORD bytesReturned = 0;

    request.operation = AETHERS_READ_WRITE_MEMORY;
    request.data.readWriteMemory.pid = pid;
    request.data.readWriteMemory.targetAddress = (PVOID)targetAddress;
    request.data.readWriteMemory.buffer = buffer;
    request.data.readWriteMemory.size = size;
    request.data.readWriteMemory.isWrite = FALSE;

    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_AETHERS_READ_WRITE_MEMORY,
        &request,
        sizeof(AETHERS_OPERATION_REQUEST),
        &response,
        sizeof(AETHERS_OPERATION_RESPONSE),
        &bytesReturned,
        NULL
    );

    if (!success)
    {
        wprintf(L"AethersReadMemory failed. Error: %lu\n", GetLastError());
        return false;
    }

    wprintf(L"AethersReadMemory succeeded. Bytes transferred: %lu\n", bytesReturned);
    return true;
}

 bool AethersWriteMemory(HANDLE hDevice, DWORD pid, LPCVOID targetAddress, PVOID buffer, SIZE_T size)
{
    AETHERS_OPERATION_REQUEST request = { };  
    AETHERS_OPERATION_RESPONSE response = { 0 };
    DWORD bytesReturned = 0;

    request.operation = AETHERS_READ_WRITE_MEMORY;
    request.data.readWriteMemory.pid = pid;
    request.data.readWriteMemory.targetAddress = (PVOID)targetAddress;
    request.data.readWriteMemory.buffer = buffer;
    request.data.readWriteMemory.size = size;
    request.data.readWriteMemory.isWrite = TRUE;

    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_AETHERS_READ_WRITE_MEMORY,
        &request,
        sizeof(AETHERS_OPERATION_REQUEST),
        &response,
        sizeof(AETHERS_OPERATION_RESPONSE),
        &bytesReturned,
        NULL
    );

    if (!success)
    {
        wprintf(L"AethersWriteMemory failed. Error: %lu\n", GetLastError());
        return false;
    }

    wprintf(L"AethersWriteMemory succeeded. Bytes transferred: %lu\n", bytesReturned);
    return true;
}

 bool AethersLockFile(HANDLE hDevice, const std::wstring& filePath)
{
    AETHERS_OPERATION_REQUEST request = { };  
    AETHERS_OPERATION_RESPONSE response = { 0 };
    DWORD bytesReturned = 0;

    request.operation = AETHERS_LOCK_UNLOCK_FILE;
    wcsncpy_s(request.data.lockUnlockFile.filePath, filePath.c_str(), _TRUNCATE);
    request.data.lockUnlockFile.lock = TRUE;

    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_AETHERS_LOCK_UNLOCK_FILE,
        &request,
        sizeof(AETHERS_OPERATION_REQUEST),
        &response,
        sizeof(AETHERS_OPERATION_RESPONSE),
        &bytesReturned,
        NULL
    );

    if (!success)
    {
        wprintf(L"AethersLockFile failed. Error: %lu\n", GetLastError());
        return false;
    }

    wprintf(L"AethersLockFile succeeded.\n");
    return true;
}

 bool AethersUnlockFile(HANDLE hDevice, const std::wstring& filePath)
{
    AETHERS_OPERATION_REQUEST request = { };  
    AETHERS_OPERATION_RESPONSE response = { 0 };
    DWORD bytesReturned = 0;

    request.operation = AETHERS_LOCK_UNLOCK_FILE;
    wcsncpy_s(request.data.lockUnlockFile.filePath, filePath.c_str(), _TRUNCATE);
    request.data.lockUnlockFile.lock = FALSE;

    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_AETHERS_LOCK_UNLOCK_FILE,
        &request,
        sizeof(AETHERS_OPERATION_REQUEST),
        &response,
        sizeof(AETHERS_OPERATION_RESPONSE),
        &bytesReturned,
        NULL
    );

    if (!success)
    {
        wprintf(L"AethersUnlockFile failed. Error: %lu\n", GetLastError());
        return false;
    }

    wprintf(L"AethersUnlockFile succeeded.\n");
    return true;
}

 bool AethersDeleteFile(HANDLE hDevice, const std::wstring& filePath)
{
    AETHERS_OPERATION_REQUEST request = { };  
    AETHERS_OPERATION_RESPONSE response = { 0 };
    DWORD bytesReturned = 0;

    request.operation = AETHERS_DELETE_FILE;
    wcsncpy_s(request.data.deleteFile.filePath, filePath.c_str(), _TRUNCATE);

    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_AETHERS_DELETE_FILE,
        &request,
        sizeof(AETHERS_OPERATION_REQUEST),
        &response,
        sizeof(AETHERS_OPERATION_RESPONSE),
        &bytesReturned,
        NULL
    );

    if (!success)
    {
        wprintf(L"AethersDeleteFile failed. Error: %lu\n", GetLastError());
        return false;
    }

    wprintf(L"AethersDeleteFile succeeded.\n");
    return true;
}

 DWORD GetProcessIdByName(const std::wstring& processName)
{
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        wprintf(L"CreateToolhelp32Snapshot failed. Error: %lu\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe))
    {
        do
        {
            if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pid;
}

 int DisplayMenu()
{
    wprintf(L"\n=== Aethers User-Mode Application ===\n");
    wprintf(L"1. Open Process\n");
    wprintf(L"2. Read Memory\n");
    wprintf(L"3. Write Memory\n");
    wprintf(L"4. Lock File\n");
    wprintf(L"5. Unlock File\n");
    wprintf(L"6. Delete File\n");
    wprintf(L"7. Open lsass.exe and Read In-Memory Strings\n");
    wprintf(L"8. Exit\n");
    wprintf(L"Enter your choice: ");
    int choice;
    std::cin >> choice;
    return choice;
}

 DWORD GetProcessIdOfHandle(HANDLE processHandle)
{
    DWORD pid = GetProcessId(processHandle);
    if (pid == 0)
    {
        wprintf(L"Failed to retrieve PID from handle. Error: %lu\n", GetLastError());
    }
    return pid;
}

bool ReadAllStrings(HANDLE hDevice, DWORD pid)
{
    HANDLE hProcess = NULL;
     if (!AethersOpenProcess(hDevice, pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, hProcess))
    {
        wprintf(L"Failed to open process for reading strings.\n");
        return false;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID address = sysInfo.lpMinimumApplicationAddress;

    while (address < sysInfo.lpMaximumApplicationAddress)
    {
        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == 0)
        {
            address = (LPCVOID)((SIZE_T)address + 0x1000);
            continue;
        }

        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_READONLY))
        {
            std::vector<BYTE> buffer(mbi.RegionSize, 0);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProcess, address, buffer.data(), mbi.RegionSize, &bytesRead))
            {
                std::string data((char*)buffer.data(), bytesRead);
                std::string currentString;
                for (SIZE_T i = 0; i < data.size(); i++)
                {
                    char c = data[i];
                    if (isprint(c))
                    {
                        currentString += c;
                         if (currentString.length() >= 4)
                        {
                            wprintf(L"String found at 0x%p: %S\n", address, currentString.c_str());
                        }
                    }
                    else
                    {
                        currentString.clear();
                    }
                }
            }
        }

        address = (LPCVOID)((SIZE_T)address + mbi.RegionSize);
    }

    CloseHandle(hProcess);
    return true;
}

#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
bool InitializeWMI(IWbemLocator** locator, IWbemServices** services) {
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM library. Error code = 0x" << std::hex << hres << std::endl;
        return false;
    }

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize security. Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return false;
    }

    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)locator);
    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator object. Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return false;
    }

    hres = (*locator)->ConnectServer(BSTR(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, services);
    if (FAILED(hres)) {
        std::cerr << "Could not connect to WMI. Error code = 0x" << std::hex << hres << std::endl;
        (*locator)->Release();
        CoUninitialize();
        return false;
    }

    hres = CoSetProxyBlanket(*services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        std::cerr << "Could not set proxy blanket. Error code = 0x" << std::hex << hres << std::endl;
        (*services)->Release();
        (*locator)->Release();
        CoUninitialize();
        return false;
    }

    return true;
}

 std::vector<DWORD> get_svchost_process_ids_by_cmdline(const std::wstring& target_cmdline) {
    std::vector<DWORD> process_ids;
    IWbemLocator* locator = NULL;
    IWbemServices* services = NULL;

    if (!InitializeWMI(&locator, &services)) {
        std::cerr << "Failed to initialize WMI." << std::endl;
        return process_ids;
    }

    IEnumWbemClassObject* enumerator = NULL;
    HRESULT hres = services->ExecQuery(
        BSTR(L"WQL"),
        BSTR(L"SELECT ProcessId, CommandLine FROM Win32_Process WHERE Name = 'svchost.exe'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &enumerator);

    if (FAILED(hres)) {
        std::cerr << "WMI query failed. Error code = 0x" << std::hex << hres << std::endl;
        services->Release();
        locator->Release();
        CoUninitialize();
        return process_ids;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (enumerator) {
        HRESULT hr = enumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (uReturn == 0) {
            break;
        }

        VARIANT vtProp;
        VARIANT vtCmdline;
        pclsObj->Get(L"ProcessId", 0, &vtProp, 0, 0);
        pclsObj->Get(L"CommandLine", 0, &vtCmdline, 0, 0);

        std::wstring cmdLine(vtCmdline.bstrVal ? vtCmdline.bstrVal : L"");

         if (cmdLine.find(target_cmdline) != std::wstring::npos) {
            DWORD pid = vtProp.uintVal;
            process_ids.push_back(pid);
         }

        VariantClear(&vtProp);
        VariantClear(&vtCmdline);
        pclsObj->Release();
    }

    enumerator->Release();
    services->Release();
    locator->Release();
    CoUninitialize();

    return process_ids;
}

 
std::vector<DWORD> get_all_process_ids(const std::wstring& process_name) {
    std::vector<DWORD> process_ids;

     HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
         return process_ids;
    }

    PROCESSENTRY32W process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32W);

     if (Process32FirstW(snapshot, &process_entry)) {
        do {
             if (_wcsicmp(process_entry.szExeFile, process_name.c_str()) == 0) {
                process_ids.push_back(process_entry.th32ProcessID);
            }
        } while (Process32NextW(snapshot, &process_entry));
    }

     CloseHandle(snapshot);
    return process_ids;
}
#include <algorithm>
#include <array>
#include <ctime>
#include <iomanip>
#include <map>
#include <sstream>
#include <windows.h>
#include <winioctl.h>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <string>
#include <set>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <shlobj.h>  
#include <knownfolders.h>

#pragma comment(lib, "wintrust.lib")

#define BUF_LEN 104857600  
struct USNEventRecord {
    ULONGLONG usn;
    DWORD reason;
    std::wstring fileName;
    std::wstring filePath;
    std::time_t timestamp;
};

void alertUser(const std::wstring& fileName, const std::wstring& filePath, const std::wstring& alertType = L"Red") {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to get console handle" << std::endl;
        return;
    }

    if (alertType == L"Red") {
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    }
    else if (alertType == L"Yellow") {
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    }
    else if (alertType == L"Green") {
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    }
    std::wcout << L"[Aethers Scanner] ALERT: " << (alertType == L"Red" ? L"Deleted/Modified File Detected: " : (alertType == L"Yellow" ? L"Security Change Detected: " : L"Nothing found in Journal")) << fileName << L" (" << filePath << L")\n";
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

bool isUnsignedFile(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileData = { 0 };
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = filePath.c_str();
    fileData.hFile = NULL;
    fileData.pgKnownSubject = NULL;

    WINTRUST_DATA winTrustData = { 0 };
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    return (status != ERROR_SUCCESS);
}

bool isPackedExecutable(const std::wstring& filePath) {
    HANDLE file = CreateFile(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD fileSize = GetFileSize(file, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize < 4096) {
        CloseHandle(file);
        return false;
    }

    BYTE* buffer = new (std::nothrow) BYTE[4096];
    if (!buffer) {
        CloseHandle(file);
        return false;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(file, buffer, 4096, &bytesRead, NULL) || bytesRead < 4096) {
        delete[] buffer;
        CloseHandle(file);
        return false;
    }

    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        delete[] buffer;
        CloseHandle(file);
        return false;
    }

    IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        delete[] buffer;
        CloseHandle(file);
        return false;
    }

    bool packed = false;
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER* sectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            buffer + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + i * sizeof(IMAGE_SECTION_HEADER));
        std::string sectionName(reinterpret_cast<char*>(sectionHeader->Name), 8);
        if (sectionName != ".text" && sectionName != ".rdata" && sectionName != ".data" && sectionName != ".pdata" && sectionName.find('\0') == std::string::npos) {
            packed = true;
            break;
        }
    }

    delete[] buffer;
    CloseHandle(file);
    return packed;
}

std::wstring getFilePathFromFRN(HANDLE volumeHandle, ULONGLONG fileReferenceNumber) {
    WCHAR filePath[MAX_PATH] = { 0 };
    DWORD bytesReturned = 0;
    FILE_ID_DESCRIPTOR fileId = { 0 };
    fileId.dwSize = sizeof(fileId);
    fileId.Type = FileIdType;
    fileId.FileId.QuadPart = fileReferenceNumber;

    HANDLE fileHandle = OpenFileById(volumeHandle, &fileId, 0, 0, NULL, 0);
    if (fileHandle != INVALID_HANDLE_VALUE) {
        if (GetFinalPathNameByHandle(fileHandle, filePath, MAX_PATH, FILE_NAME_NORMALIZED) > 0) {
            CloseHandle(fileHandle);
            return filePath;
        }
        CloseHandle(fileHandle);
    }
    return L"Unknown Path";
}

std::wstring getCurrentUserDirectory() {
    PWSTR userProfilePath = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Profile, 0, NULL, &userProfilePath))) {
        std::wstring userDirectory(userProfilePath);
        CoTaskMemFree(userProfilePath);
        return userDirectory;
    }
    return L"C:\\Users\\Unknown";
}



bool isExcludedPath(const std::wstring& path) {
    std::vector<std::wstring> excludedPaths = {
        L"C:\\Windows",
        L"C:\\Windows\\System32",
        L"C:\\Windows\\SysWOW64"
    };
    for (const auto& excluded : excludedPaths) {
        if (path.find(excluded) == 0) {
            return true;
        }
    }
    return false;
}
#pragma comment(lib, "advapi32.lib")

struct USN_RECORD_V3_CUSTOM {
    DWORD RecordLength;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORDLONG FileReferenceNumber;
    DWORDLONG ParentFileReferenceNumber;
    USN Usn;
    LARGE_INTEGER TimeStamp;
    DWORD Reason;
    DWORD SourceInfo;
    DWORD SecurityId;
    DWORD FileAttributes;
    WORD  FileNameLength;
    WORD  FileNameOffset;
    WCHAR FileName[1];
};

struct USN_RECORD_CUSTOM {
    DWORD RecordLength;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORDLONG FileReferenceNumber;
    DWORDLONG ParentFileReferenceNumber;
    USN Usn;
    LARGE_INTEGER TimeStamp;
    DWORD Reason;
    DWORD SourceInfo;
    DWORD SecurityId;
    DWORD FileAttributes;
    WORD  FileNameLength;
    WORD  FileNameOffset;
    WCHAR FileName[1];
};

using namespace std;



#include <setupapi.h>
#include <winioctl.h>
#include <devguid.h>
#include <initguid.h>
#include <usbiodef.h>

#pragma comment(lib, "Setupapi.lib")

void CheckUSBDevices() {
    char driveStrings[256];
    DWORD driveStringLength = GetLogicalDriveStringsA(sizeof(driveStrings), driveStrings);
    if (driveStringLength == 0) {
        return;
    }

    char* drive = driveStrings;
    while (*drive) {
        UINT driveType = GetDriveTypeA(drive);
        if (driveType == DRIVE_REMOVABLE) {
            HANDLE hDevice = CreateFileA(drive, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (hDevice != INVALID_HANDLE_VALUE) {
                STORAGE_PROPERTY_QUERY query = { StorageDeviceProperty, PropertyStandardQuery };
                STORAGE_DEVICE_DESCRIPTOR deviceDescriptor = { 0 };
                deviceDescriptor.Size = sizeof(STORAGE_DEVICE_DESCRIPTOR);
                DWORD bytesRead = 0;

                if (DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), &deviceDescriptor, sizeof(deviceDescriptor), &bytesRead, NULL)) {
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    cout << "[Trace] USB/HDD detected: " << drive << endl;
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                }
                CloseHandle(hDevice);
            }
        }
        drive += strlen(drive) + 1;
    }
}

void CheckRemovedDevices() {
    HDEVINFO deviceInfoSet = SetupDiGetClassDevs(NULL, L"USB", NULL, DIGCF_ALLCLASSES);
    if (deviceInfoSet == INVALID_HANDLE_VALUE) {
        return;
    }

    SP_DEVINFO_DATA deviceInfoData;
    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    DWORD index = 0;
    while (SetupDiEnumDeviceInfo(deviceInfoSet, index, &deviceInfoData)) {
        index++;

        WCHAR deviceId[MAX_PATH];
        if (SetupDiGetDeviceInstanceIdW(deviceInfoSet, &deviceInfoData, deviceId, MAX_PATH, NULL)) {
            DWORD dataType;
            BYTE buffer[4096];
            WCHAR driveLetter[MAX_PATH] = L"";
            if (SetupDiGetDeviceRegistryPropertyW(deviceInfoSet, &deviceInfoData, SPDRP_REMOVAL_POLICY, &dataType, buffer, sizeof(buffer), NULL)) {
                wstring policy((wchar_t*)buffer);
                if (policy.find(L"FAT") != wstring::npos || policy.find(L"FAT32") != wstring::npos) {
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
                    wcout << L"[Warning] USB/HDD previously removed or formatted (FAT/FAT32): " << deviceId;
                    if (SetupDiGetDeviceRegistryPropertyW(deviceInfoSet, &deviceInfoData, SPDRP_LOCATION_INFORMATION, &dataType, (PBYTE)driveLetter, sizeof(driveLetter), NULL)) {
                     }
                    wcout << endl;
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                }
                else {
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    wcout << L"[Trace] USB/HDD detected: " << deviceId;
                    if (SetupDiGetDeviceRegistryPropertyW(deviceInfoSet, &deviceInfoData, SPDRP_LOCATION_INFORMATION, &dataType, (PBYTE)driveLetter, sizeof(driveLetter), NULL)) {
                     }
                    wcout << endl;
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                }
            }
        }
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet);
}
void EnumerateRegistryKeys(HKEY rootKey, const wstring& subKey) {
    HKEY hKey;
    if (RegOpenKeyEx(rootKey, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        wcout << L"Failed to open registry key: " << subKey << endl;
        return;
    }

    DWORD index = 0;
    WCHAR keyName[256];
    DWORD keyNameSize = sizeof(keyName) / sizeof(WCHAR);

    while (RegEnumKeyEx(hKey, index, keyName, &keyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        wcout << L"[Trace] Found registry key: " << keyName << endl;
        keyNameSize = sizeof(keyName) / sizeof(WCHAR);
        index++;
    }

    RegCloseKey(hKey);
}

void CheckRemovedRegistryKeys() {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        wcout << L"Failed to open registry key: SYSTEM\\CurrentControlSet\\Enum\\USBSTOR" << endl;
        return;
    }

    DWORD index = 0;
    WCHAR keyName[256];
    DWORD keyNameSize = sizeof(keyName) / sizeof(WCHAR);

    while (RegEnumKeyEx(hKey, index, keyName, &keyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        bool deleted = true;
        HKEY subKey;
        if (RegOpenKeyEx(hKey, keyName, 0, KEY_READ, &subKey) == ERROR_SUCCESS) {
            deleted = false;
            RegCloseKey(subKey);
        }
        if (deleted) {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
            wcout << L"[Warning] Potential deleted registry key: " << keyName << endl;
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
        index++;
        keyNameSize = sizeof(keyName) / sizeof(WCHAR);
    }

    RegCloseKey(hKey);
}
void CheckEventLogModifications(const wstring& logName) {
    HANDLE hEventLog = OpenEventLog(NULL, logName.c_str());
    if (hEventLog == NULL) {
        wcout << L"Failed to open event log: " << logName << endl;
        return;
    }

    EVENTLOGRECORD* pRecord;
    BYTE buffer[4096];
    DWORD bytesRead = 0, minBytesNeeded = 0;

    if (!ReadEventLog(hEventLog, EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ, 0, buffer, sizeof(buffer), &bytesRead, &minBytesNeeded)) {
        wcout << L"Failed to read event log: " << logName << endl;
        CloseEventLog(hEventLog);
        return;
    }

    pRecord = (EVENTLOGRECORD*)buffer;
    while ((BYTE*)pRecord < buffer + bytesRead) {
        wcout << L"[Log] Event ID: " << pRecord->EventID << L", Source: " << (LPWSTR)((BYTE*)pRecord + sizeof(EVENTLOGRECORD));
        wcout << L", Event Type: " << pRecord->EventType;
        wcout << L", Record Number: " << pRecord->RecordNumber;
        wcout << L", Time Generated: " << pRecord->TimeGenerated << endl;
        pRecord = (EVENTLOGRECORD*)((BYTE*)pRecord + pRecord->Length);
    }

    CloseEventLog(hEventLog);
}

void SearchRAM() {
    SetDebugPrivileges();
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    LPBYTE minAddress = (LPBYTE)sysInfo.lpMinimumApplicationAddress;
    LPBYTE maxAddress = (LPBYTE)sysInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION memInfo;
    char* buffer;

    HANDLE hDevice = CreateFileA("\\\\.\\Aethers9185317", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        wcout << L"Failed to open Aethers device." << endl;
        return;
    }

    DWORD memoryCompressionPid = 0;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry)) {
        do {
            if (wcscmp(entry.szExeFile, L"Memory Compression") == 0) {
                memoryCompressionPid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    if (memoryCompressionPid == 0) {
        wcout << L"[Debug] Memory Compression PID not found." << endl;
        CloseHandle(hDevice);
        return;
    }
    ACCESS_MASK desiredAccess = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

    HANDLE processHandle = NULL;
    HANDLE aethersProcessHandle = AethersOpenProcess(hDevice, memoryCompressionPid, desiredAccess, processHandle);
    if (aethersProcessHandle == NULL || aethersProcessHandle == INVALID_HANDLE_VALUE) {
        wcout << L"[Debug] Failed to open process handle for Memory Compression." << endl;
        CloseHandle(hDevice);
        return;
    }
    else {
        wcout << L"[Debug] Successfully opened process handle for Memory Compression." << endl;
    }

    vector<string> targets = {   "skript.gg", "tzxproject", "keyauth", "+skript.gg", "imgui"};

    StringCleaner ahrsawaw(memoryCompressionPid, targets);
    ahrsawaw.findStrings(aethersProcessHandle);

    CloseHandle(aethersProcessHandle);
    CloseHandle(hDevice);
}
#include <filesystem>

namespace fs = std::filesystem;
bool searchExtensionlessFile(const std::wstring& directory) {
    for (const auto& entry : fs::directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            std::wstring fileName = entry.path().filename().wstring();
            size_t length = fileName.length();
            if (length >= 5 && length <= 15 && fileName.find(L'.') == std::wstring::npos) {
                alertUser(fileName, entry.path().wstring(), L"Red");
                return true;
            }
        }
    }
    return false;
}

int jrnlcheck() {
    std::wstring userDirectory = getCurrentUserDirectory();

    HANDLE hVol = CreateFile(TEXT("\\\\.\\c:"),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hVol == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateFile failed with error: " << GetLastError() << "\n";
        return 1;
    }

    USN_JOURNAL_DATA_V0 journalData = {};
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hVol,
        FSCTL_QUERY_USN_JOURNAL,
        NULL,
        0,
        &journalData,
        sizeof(journalData),
        &bytesReturned,
        NULL)) {
        std::cerr << "FSCTL_QUERY_USN_JOURNAL failed with error: " << GetLastError() << "\n";
        CloseHandle(hVol);
        return 1;
    }

    READ_USN_JOURNAL_DATA_V0 readData = { 0 };
    readData.StartUsn = journalData.FirstUsn;
    readData.ReasonMask = USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME | USN_REASON_FILE_DELETE | USN_REASON_SECURITY_CHANGE | USN_REASON_FILE_CREATE | USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND;
    readData.UsnJournalID = journalData.UsnJournalID;
    readData.BytesToWaitFor = 0;
    readData.Timeout = 0;

    CHAR* buffer = new (std::nothrow) CHAR[BUF_LEN];
    if (buffer == nullptr) {
        std::cerr << "Failed to allocate memory for buffer.\n";
        CloseHandle(hVol);
        return 1;
    }

    DWORD bytesRead = 0;

    if (!DeviceIoControl(hVol,
        FSCTL_READ_USN_JOURNAL,
        &readData,
        sizeof(readData),
        buffer,
        BUF_LEN,
        &bytesRead,
        NULL)) {
        std::cerr << "FSCTL_READ_USN_JOURNAL failed with error: " << GetLastError() << "\n";
        delete[] buffer;
        CloseHandle(hVol);
        return 1;
    }

    if (bytesRead < sizeof(USN)) {
        std::cerr << "Invalid bytes read: " << bytesRead << "\n";
        delete[] buffer;
        CloseHandle(hVol);
        return 1;
    }

    DWORD retBytes = bytesRead - sizeof(USN);
    PUSN_RECORD usnRecord = (PUSN_RECORD)(buffer + sizeof(USN));
    bool alertTriggered = false;

    while (retBytes > 0) {
        if (usnRecord->RecordLength == 0 || usnRecord->RecordLength > retBytes) {
            std::cerr << "Invalid record length encountered.\n";
            break;
        }

        try {
            std::wstring fileName(usnRecord->FileName, usnRecord->FileNameLength / sizeof(WCHAR));
            std::wstring filePath = getFilePathFromFRN(hVol, usnRecord->FileReferenceNumber);

            if (filePath.find(L"C:\\Windows\\WinSxS\\") != std::wstring::npos) {
                retBytes -= usnRecord->RecordLength;
                usnRecord = (PUSN_RECORD)(((PCHAR)usnRecord) + usnRecord->RecordLength);
                continue;
            }

            if ((filePath.find(userDirectory) != std::wstring::npos) &&
                (filePath.find(L"\\Downloads\\") != std::wstring::npos ||
                    filePath.find(L"\\Documents\\") != std::wstring::npos ||
                    filePath.find(L"\\Music\\") != std::wstring::npos)) {
                if ((usnRecord->Reason & (USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME | USN_REASON_FILE_CREATE | USN_REASON_DATA_OVERWRITE | USN_REASON_FILE_DELETE))) {
                    if (isUnsignedFile(filePath) || isPackedExecutable(filePath)) {
                        std::wstring alertType = (fileName.find(L".exe") != std::wstring::npos) ? L"Yellow" : L"Red";
                        alertUser(fileName, filePath, alertType);
                        alertTriggered = true;
                    }
                }
            }

            if (filePath.find(L"C:\\Windows\\Prefetch\\") == 0 && (usnRecord->Reason & USN_REASON_SECURITY_CHANGE)) {
                alertUser(fileName, filePath, L"Yellow");
                alertTriggered = true;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Exception occurred while processing record: " << e.what() << "\n";
            break;
        }

        retBytes -= usnRecord->RecordLength;
        usnRecord = (PUSN_RECORD)(((PCHAR)usnRecord) + usnRecord->RecordLength);
    }

    if (!alertTriggered) {
        alertUser(L"", L"", L"Green");
    }

    delete[] buffer;
    CloseHandle(hVol);

    if (searchExtensionlessFile(L"C:\\Windows\\System32")) {
        alertTriggered = true;
    }

    return alertTriggered ? 1 : 0;
}
wstring ConvertToWideString(const char* str, size_t length) {
    wstring wstr;
    for (size_t i = 0; i < length; ++i) {
        if (str[i] == '\0') break;
        wstr += static_cast<wchar_t>(str[i]);
    }
    return wstr;
}
 

void ListAllUSNEntries(const wstring& drive) {
    HANDLE hVolume = CreateFileW((L"\\\\.\\" + drive).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hVolume == INVALID_HANDLE_VALUE) {
        wcout << L"Failed to open volume: " << drive << L" Error: " << GetLastError() << endl;
        return;
    }

    USN_JOURNAL_DATA journalData;
    DWORD bytesReturned;
    if (!DeviceIoControl(hVolume, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &journalData, sizeof(journalData), &bytesReturned, NULL)) {
        wcout << L"Failed to query USN journal: " << GetLastError() << endl;
        CloseHandle(hVolume);
        return;
    }

    MFT_ENUM_DATA mftEnumData = { 0 };
    mftEnumData.StartFileReferenceNumber = 0;
    mftEnumData.LowUsn = 0;
    mftEnumData.HighUsn = journalData.MaxUsn;

    BYTE buffer[4096];
    DWORD bytesRead;
    while (DeviceIoControl(hVolume, FSCTL_ENUM_USN_DATA, &mftEnumData, sizeof(mftEnumData), buffer, sizeof(buffer), &bytesRead, NULL)) {
        if (bytesRead < sizeof(USN)) {
            break;
        }
        USN_RECORD* usnRecord = (USN_RECORD*)(buffer + sizeof(USN));
        while ((BYTE*)usnRecord < buffer + bytesRead) {
            wstring fileName(usnRecord->FileName, usnRecord->FileNameLength / sizeof(WCHAR));
            wcout << L"USN Entry: " << fileName << L", Reason: " << usnRecord->Reason << endl;
            usnRecord = (USN_RECORD*)((BYTE*)usnRecord + usnRecord->RecordLength);
        }
    }

    if (GetLastError() != ERROR_HANDLE_EOF && GetLastError() != ERROR_NO_MORE_ITEMS) {
        wcout << L"Error while reading USN journal: " << GetLastError() << endl;
    }

    CloseHandle(hVolume);
}


void ReadBAMAndCheckExe() {
    HKEY hKey;
    std::cout << "a";
     LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Bam\\State\\UserSettings",
        0,
        KEY_READ,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        wcerr << L"Failed to open BAM registry key. Error code: " << result << endl;
        return;
    }
    std::cout << "a";

    DWORD index = 0;
    WCHAR valueName[256];
    BYTE data[4096];
    DWORD valueNameSize;
    DWORD dataSize;
    DWORD valueType;
    std::cout << "a";

     while (true) {
 
        valueNameSize = sizeof(valueName) / sizeof(WCHAR);  
        dataSize = sizeof(data);  
        result = RegEnumValueW(
            hKey,
            index,
            valueName,
            &valueNameSize,
            NULL,
            &valueType,
            data,
            &dataSize
        );



       

         if (valueType == REG_BINARY) {
            wstring exePath(valueName);
            if (exePath.find(L".exe") != wstring::npos) {
                wcout << L"Checking: " << exePath << endl;
                try {
                    fs::path path(exePath);
                    if (fs::exists(path) && fs::is_regular_file(path)) {
                        wcout << L"[Debug] File exists and is a regular file." << endl;

                         ifstream file(path, ios::binary);
                        if (!file) {
                            wcerr << L"[Error] Failed to open file: " << exePath << endl;
                            index++;
                            continue;
                        }

                         IMAGE_DOS_HEADER dosHeader;
                        file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
                        if (file.gcount() != sizeof(dosHeader) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                            wcout << L"[Debug] Invalid DOS header for: " << exePath << endl;
                            file.close();
                            index++;
                            continue;
                        }
                        wcout << L"[Debug] Valid DOS header found." << endl;

                         file.seekg(dosHeader.e_lfanew, ios::beg);
                        DWORD ntSignature;
                        file.read(reinterpret_cast<char*>(&ntSignature), sizeof(ntSignature));
                        if (file.gcount() != sizeof(ntSignature) || ntSignature != IMAGE_NT_SIGNATURE) {
                            wcout << L"[Debug] Invalid NT header signature for: " << exePath << endl;
                            file.close();
                            index++;
                            continue;
                        }
                        wcout << L"[Debug] Valid NT signature found." << endl;

                         IMAGE_FILE_HEADER fileHeader;
                        file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
                        if (file.gcount() != sizeof(fileHeader)) {
                            wcout << L"[Debug] Failed to read File Header for: " << exePath << endl;
                            file.close();
                            index++;
                            continue;
                        }

                         WORD magic;
                        file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
                        if (file.gcount() != sizeof(magic)) {
                            wcout << L"[Debug] Failed to read Optional Header Magic for: " << exePath << endl;
                            file.close();
                            index++;
                            continue;
                        }

                        bool is64Bit = false;
                        if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                            is64Bit = false;
                        }
                        else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                            is64Bit = true;
                        }
                        else {
                            wcout << L"[Debug] Unknown Optional Header Magic for: " << exePath << endl;
                            file.close();
                            index++;
                            continue;
                        }

                         file.seekg(dosHeader.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
                            (is64Bit ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32)), ios::beg);

                         vector<IMAGE_SECTION_HEADER> sectionHeaders;
                        for (WORD i = 0; i < fileHeader.NumberOfSections; ++i) {
                            IMAGE_SECTION_HEADER sectionHeader;
                            file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(sectionHeader));
                            if (file.gcount() != sizeof(sectionHeader)) {
                                wcout << L"[Error] Failed to read section header " << i + 1 << L" for: " << exePath << endl;
                                break;
                            }
                            sectionHeaders.push_back(sectionHeader);
                            wstring sectionName = ConvertToWideString(reinterpret_cast<const char*>(sectionHeader.Name), 8);
                            wcout << L"[Debug] Section: " << sectionName
                                << L", Virtual Size: " << sectionHeader.Misc.VirtualSize
                                << L", Raw Size: " << sectionHeader.SizeOfRawData << endl;
                        }

                         if (fileHeader.NumberOfSections > 5) {
                             SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
                            wcout << L"[Warning] Potential packed/obfuscated executable detected: "
                                << exePath << L" (Sections: " << fileHeader.NumberOfSections << L")" << endl;
                             SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                        }

                        file.close();

                         ifstream fileCheck(path, ios::binary);
                        if (fileCheck.is_open()) {
                            char buffer[2];
                            fileCheck.read(buffer, 2);
                            if (fileCheck.gcount() == 2 && buffer[0] == 'U' && buffer[1] == 'P') {
                                 SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
                                wcout << L"[Warning] Packed executable detected (starts with 'UP'): " << exePath << endl;
                                 SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                            }
                            fileCheck.close();
                        }
                        else {
                            wcerr << L"[Error] Failed to reopen file for checking: " << exePath << endl;
                        }
                    }
                    else {
                        wcout << L"[Debug] Executable path does not exist or is not a regular file: " << exePath << endl;
                    }
                }
                catch (const fs::filesystem_error& e) {
                    wcerr << L"[Error] Filesystem error: " << e.what() << endl;
                }
                catch (const exception& e) {
                    wcerr << L"[Error] Exception: " << e.what() << endl;
                }
            }
        }
        index++;
    }

    RegCloseKey(hKey);
}
#define _WIN32_WINNT 0x0600

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <ctime>
#include <winioctl.h>
#include <wbemidl.h>
#include <comdef.h>
#include <softpub.h>
#include <wintrust.h>
#include <cryptuiapi.h>
 #include <shlwapi.h>
#include <winevt.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "cryptui.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wevtapi.lib")

#define FOREGROUND_YELLOW (FOREGROUND_RED | FOREGROUND_GREEN)

void sub_519358913581358(const std::string& u_11223)
{
    std::ofstream u_998877("device_log.txt", std::ios::app);
    if (u_998877.is_open())
    {
        u_998877 << u_11223 << std::endl;
        u_998877.close();
    }
}

void sub_78658698274623(const std::string& u_11223, WORD u_999)
{
    HANDLE u_76543 = GetStdHandle(STD_OUTPUT_HANDLE);
    if (u_76543 == INVALID_HANDLE_VALUE || u_76543 == nullptr)
    {
        std::cout << u_11223 << std::endl;
        return;
    }

    SetConsoleTextAttribute(u_76543, u_999);
    std::cout << u_11223 << std::endl;
    SetConsoleTextAttribute(u_76543, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void sub_9876543210987654321()
{
    HANDLE u_12345 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (u_12345 == INVALID_HANDLE_VALUE)
    {
        return;
    }

    PROCESSENTRY32 u_112233;
    u_112233.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(u_12345, &u_112233))
    {
        CloseHandle(u_12345);
        return;
    }

    do
    {
        if (std::wstring(u_112233.szExeFile) == L"lsass.exe")
        {
            HANDLE u_23456 = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, u_112233.th32ProcessID);
            if (u_23456 == NULL)
            {
                CloseHandle(u_12345);
                return;
            }

            std::vector<std::string> u_998877 = {
                "skript.gg",
                "keyauth.win",
                "api.tzproject.com",
                "tzproject.com"
            };

            char u_38476[4096];
            SIZE_T u_98304;
            for (size_t u_394820 = 0; u_394820 < u_112233.dwSize; u_394820 += sizeof(u_38476))
            {
                if (ReadProcessMemory(u_23456, (LPCVOID)u_394820, u_38476, sizeof(u_38476), &u_98304))
                {
                    for (const auto& u_556677 : u_998877)
                    {
                        if (std::string(u_38476, u_98304).find(u_556677) != std::string::npos)
                        {
                            std::string u_111222 = "Warning: Found " + u_556677 + " in z memory.";
                            sub_78658698274623(u_111222, FOREGROUND_RED | FOREGROUND_INTENSITY);
                            sub_519358913581358(u_111222);
                        }
                    }
                }
            }

            CloseHandle(u_23456);
        }
    } while (Process32Next(u_12345, &u_112233));

    CloseHandle(u_12345);
}

void sub_9876543210987654322()
{
    WIN32_FIND_DATA u_112233;
    HANDLE u_12345 = FindFirstFile(L"C:\\Windows\\Prefetch\\*", &u_112233);
    bool u_45678 = true;
    SYSTEMTIME u_20394, u_405060;

    GetSystemTime(&u_20394);

    if (u_12345 == INVALID_HANDLE_VALUE)
    {
        sub_78658698274623("Prefetch folder is locked or inaccessible.", FOREGROUND_RED | FOREGROUND_INTENSITY);
        sub_519358913581358("Prefetch folder is locked or inaccessible.");
        return;
    }

    while (FindNextFile(u_12345, &u_112233))
    {
        if (!(u_112233.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            FILETIME u_76543 = u_112233.ftLastWriteTime;
            FileTimeToSystemTime(&u_76543, &u_405060);

            if (u_20394.wYear == u_405060.wYear &&
                u_20394.wMonth == u_405060.wMonth &&
                (u_20394.wDay == u_405060.wDay || u_20394.wDay - u_405060.wDay <= 3))
            {
                u_45678 = false;
            }
        }
    }

    if (!u_45678)
    {
        sub_78658698274623("Warning: Prefetch folder has been cleared recently.", FOREGROUND_RED | FOREGROUND_INTENSITY);
        sub_519358913581358("Warning: Prefetch folder has been cleared recently.");
    }

    FindClose(u_12345);
}

void sub_9876543210987654323()
{
    SERVICE_STATUS_PROCESS u_111222;
    DWORD u_12345;

    SC_HANDLE u_45678 = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!u_45678)
    {
        return;
    }

    SC_HANDLE u_98765 = OpenService(u_45678, L"SysMain", SERVICE_QUERY_STATUS);
    if (u_98765)
    {
        if (QueryServiceStatusEx(u_98765, SC_STATUS_PROCESS_INFO, (LPBYTE)&u_111222, sizeof(SERVICE_STATUS_PROCESS), &u_12345))
        {
            if (u_111222.dwCurrentState != SERVICE_RUNNING)
            {
                sub_78658698274623("Warning: SysMain service is disabled.", FOREGROUND_RED | FOREGROUND_INTENSITY);
                sub_519358913581358("Warning: SysMain service is disabled.");
            }
        }
        CloseServiceHandle(u_98765);
    }

    SC_HANDLE u_56789 = OpenService(u_45678, L"wuauserv", SERVICE_QUERY_STATUS);
    if (u_56789)
    {
        if (QueryServiceStatusEx(u_56789, SC_STATUS_PROCESS_INFO, (LPBYTE)&u_111222, sizeof(SERVICE_STATUS_PROCESS), &u_12345))
        {
            if (u_111222.dwCurrentState != SERVICE_RUNNING)
            {
                sub_78658698274623("Warning: Windows Update service is disabled.", FOREGROUND_RED | FOREGROUND_INTENSITY);
                sub_519358913581358("Warning: Windows Update service is disabled.");
            }
        }
        CloseServiceHandle(u_56789);
    }

    CloseServiceHandle(u_45678);
}

void sub_9876543210987654324()
{
    SYSTEMTIME u_112233;
    GetSystemTime(&u_112233);

    DWORD u_34567 = GetTickCount64();
    DWORD u_45678 = u_34567 / 1000 / 60 / 60;
    std::string u_56789 = "System uptime: " + std::to_string(u_45678) + " hours.";
    sub_78658698274623(u_56789, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    sub_519358913581358(u_56789);

    HANDLE u_12345 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (u_12345 == INVALID_HANDLE_VALUE)
    {
        return;
    }

    PROCESSENTRY32 u_20394;
    u_20394.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(u_12345, &u_20394))
    {
        do
        {
            if (std::wstring(u_20394.szExeFile) == L"explorer.exe")
            {
                HANDLE u_34567 = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, u_20394.th32ProcessID);
                if (u_34567)
                {
                    FILETIME u_56789, u_67890, u_78901, u_89012;
                    if (GetProcessTimes(u_34567, &u_56789, &u_67890, &u_78901, &u_89012))
                    {
                        ULARGE_INTEGER u_90123;
                        u_90123.LowPart = u_56789.dwLowDateTime;
                        u_90123.HighPart = u_56789.dwHighDateTime;

                        DWORD u_67890 = (GetTickCount64() - u_90123.QuadPart / 10000) / 1000 / 60 / 60;

                        if (u_45678 - u_67890 >= 1)
                        {
                            sub_78658698274623("Warning: explorer.exe has been restarted recently.", FOREGROUND_RED | FOREGROUND_INTENSITY);
                            sub_519358913581358("Warning: explorer.exe has been restarted recently.");
                        }
                    }
                    CloseHandle(u_34567);
                }
            }
        } while (Process32Next(u_12345, &u_20394));
    }
    CloseHandle(u_12345);
}

#include <windows.h>
 #include <iostream>
#include <string>
#include <vector>

bool sub_98765432112345678901(const std::wstring& volume)
{
    HANDLE u_23456 = CreateFileW(volume.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (u_23456 == INVALID_HANDLE_VALUE)
    {
        sub_78658698274623("Unable to open volume for NTFS metadata analysis.", FOREGROUND_RED | FOREGROUND_INTENSITY);
        sub_519358913581358("Unable to open volume for NTFS metadata analysis.");
        return false;
    }

    DWORD u_876543;
    NTFS_VOLUME_DATA_BUFFER u_112233;

    if (!DeviceIoControl(u_23456, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &u_112233, sizeof(u_112233), &u_876543, NULL))
    {
        CloseHandle(u_23456);
        sub_78658698274623("Unable to retrieve NTFS volume data.", FOREGROUND_RED | FOREGROUND_INTENSITY);
        sub_519358913581358("Unable to retrieve NTFS volume data.");
        return false;
    }

    const char* ntfs_metadata_files[] = { "\\$LogFile", "\\$J", "\\$MFT", "\\$Secure" };

    for (const auto& file : ntfs_metadata_files)
    {
        std::wstring path = volume + std::wstring(file, file + strlen(file));
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            sub_78658698274623("Unable to open NTFS metadata file: " + std::string(file), FOREGROUND_RED | FOREGROUND_INTENSITY);
            sub_519358913581358("Unable to open NTFS metadata file: " + std::string(file));
            continue;
        }
        else
        {
            FILETIME creationTime, lastAccessTime, lastWriteTime;
            if (GetFileTime(hFile, &creationTime, &lastAccessTime, &lastWriteTime))
            {
                SYSTEMTIME stUTC, stLocal;
                FileTimeToSystemTime(&lastWriteTime, &stUTC);
                SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

                SYSTEMTIME currentTime;
                GetLocalTime(&currentTime);

                if (CompareFileTime(&lastWriteTime, &creationTime) == 1)
                {
                    sub_78658698274623("[Aethers Scanner] NTFS metadata file " + std::string(file) + " has a future modification date.", FOREGROUND_RED | FOREGROUND_INTENSITY);
                }
                else if (stLocal.wYear == currentTime.wYear && stLocal.wMonth == currentTime.wMonth && abs(stLocal.wDay - currentTime.wDay) <= 1)
                {
                    sub_78658698274623("[Aethers Scanner] " + std::string(file) + " changed at: " + std::to_string(stLocal.wDay) + "/" + std::to_string(stLocal.wMonth) + "/" + std::to_string(stLocal.wYear), FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
                }
                else
                {
                    sub_78658698274623("[Aethers Scanner] NTFS data is GOOD! Last modified: " + std::to_string(stLocal.wDay) + "/" + std::to_string(stLocal.wMonth) + "/" + std::to_string(stLocal.wYear), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                }

                LARGE_INTEGER fileSize;
                if (GetFileSizeEx(hFile, &fileSize))
                {
                    if (fileSize.QuadPart < 10240 || fileSize.QuadPart == 1048576 || fileSize.QuadPart == 2097152 || fileSize.QuadPart == 10485760)
                    {
                        sub_78658698274623("[Aethers Scanner] " + std::string(file) + " file size suspicious: " + std::to_string(fileSize.QuadPart) + " bytes", FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
                    }
                }
            }
            CloseHandle(hFile);
        }
    }

    CloseHandle(u_23456);
    return true;
}

void sub_98765432101234567890(const std::wstring& u_394820, const std::vector<std::wstring>& u_776655)
{
    WIN32_FIND_DATA u_998877;
    HANDLE u_12345 = FindFirstFile((u_394820 + L"\\*").c_str(), &u_998877);

    if (u_12345 == INVALID_HANDLE_VALUE)
    {
        return;
    }

    do
    {
        const std::wstring u_203945(u_998877.cFileName);

        if (u_998877.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (u_203945 != L"." && u_203945 != L"..")
            {
                sub_98765432101234567890(u_394820 + L"\\" + u_203945, u_776655);
            }
        }
        else
        {
            for (const auto& u_556677 : u_776655)
            {
                if (u_203945 == u_556677)
                {
                    std::wstring u_444555 = L"Warning: Found " + u_556677 + L" at " + u_394820 + L"\\" + u_203945;
                    std::string u_11223(u_444555.begin(), u_444555.end());
                    sub_78658698274623(u_11223, FOREGROUND_RED | FOREGROUND_INTENSITY);
                    sub_519358913581358(u_11223);
                }
            }
        }
    } while (FindNextFile(u_12345, &u_998877) != 0);

    FindClose(u_12345);
}
#define SECTOR_SIZE 512
#define BUFFER_SIZE 65536
bool readDiskSectors(HANDLE diskHandle, std::vector<std::string>& sectorData, DWORD startSector, DWORD sectorCount)
{
    DWORD bytesRead;
    BYTE buffer[SECTOR_SIZE];

    LARGE_INTEGER sectorOffset;
    sectorOffset.QuadPart = static_cast<LONGLONG>(startSector) * SECTOR_SIZE;

    for (DWORD i = 0; i < sectorCount; ++i)
    {
        if (SetFilePointerEx(diskHandle, sectorOffset, NULL, FILE_BEGIN) == 0)
        {
            std::cerr << "Failed to set file pointer. Error: " << GetLastError() << std::endl;
            return false;
        }

        if (!ReadFile(diskHandle, buffer, SECTOR_SIZE, &bytesRead, NULL) || bytesRead != SECTOR_SIZE)
        {
            std::cerr << "Failed to read sector. Error: " << GetLastError() << std::endl;
            return false;
        }

        sectorData.push_back(std::string(buffer, buffer + SECTOR_SIZE));
        sectorOffset.QuadPart += SECTOR_SIZE;
    }
    return true;
}
bool sub_09876543211234567890()
{
    bool u_99999 = true;
    HRESULT u_11223;

    u_11223 = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(u_11223))
    {
        return false;
    }

    u_11223 = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );

    if (FAILED(u_11223))
    {
        CoUninitialize();
        return false;
    }

    IWbemLocator* u_998877 = NULL;

    u_11223 = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&u_998877);

    if (FAILED(u_11223))
    {
        CoUninitialize();
        return false;
    }

    IWbemServices* u_786564 = NULL;

    u_11223 = u_998877->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &u_786564
    );

    if (FAILED(u_11223))
    {
        u_998877->Release();
        CoUninitialize();
        return false;
    }

    u_11223 = CoSetProxyBlanket(
        u_786564,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(u_11223))
    {
        u_786564->Release();
        u_998877->Release();
        CoUninitialize();
        return false;
    }

    IEnumWbemClassObject* u_18273645 = NULL;
    u_11223 = u_786564->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2 OR EventType = 3"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &u_18273645);

    if (FAILED(u_11223))
    {
        u_786564->Release();
        u_998877->Release();
        CoUninitialize();
        return false;
    }

    IWbemClassObject* u_554433 = NULL;
    ULONG u_777777 = 0;

    while (u_18273645)
    {
        HRESULT hr = u_18273645->Next(WBEM_INFINITE, 1, &u_554433, &u_777777);

        if (0 == u_777777)
        {
            break;
        }

        VARIANT u_111111;

        hr = u_554433->Get(L"DriveName", 0, &u_111111, 0, 0);
        if (SUCCEEDED(hr) && u_111111.vt == VT_BSTR)
        {
            std::wstring ws(u_111111.bstrVal, SysStringLen(u_111111.bstrVal));
            std::string u_202020(ws.begin(), ws.end());

            hr = u_554433->Get(L"EventType", 0, &u_111111, 0, 0);
            if (SUCCEEDED(hr) && u_111111.vt == VT_UINT)
            {
                std::string u_303030 = (u_111111.uintVal == 2) ? "connected" : "disconnected";
                std::string u_404040 = "Drive " + u_202020 + " has been " + u_303030;

                sub_78658698274623(u_404040, FOREGROUND_RED | FOREGROUND_INTENSITY);
                sub_519358913581358(u_404040);
                u_99999 = false;
            }
        }

        VariantClear(&u_111111);
        u_554433->Release();
    }

    u_786564->Release();
    u_998877->Release();
    u_18273645->Release();
    CoUninitialize();

    return u_99999;
}

void sub_9876543210987654325()
{
    HANDLE hDevice = CreateFile(L"\\\\.\\GlobalRoot", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        sub_78658698274623("Failed to open GlobalRoot for IOCTL scanning.", FOREGROUND_RED | FOREGROUND_INTENSITY);
        sub_519358913581358("Failed to open GlobalRoot for IOCTL scanning.");
        return;
    }

    std::vector<std::wstring> suspicious_devices;
    DWORD bytesReturned;
    char buffer[4096];

    if (DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, NULL, 0, buffer, sizeof(buffer), &bytesReturned, NULL))
    {
        sub_78658698274623("Scanned IOCTL devices successfully.", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        sub_519358913581358("Scanned IOCTL devices successfully.");
    }
    else
    {
        sub_78658698274623("Failed to query IOCTL devices.", FOREGROUND_RED | FOREGROUND_INTENSITY);
        sub_519358913581358("Failed to query IOCTL devices.");
    }

    CloseHandle(hDevice);
}

bool sub_9876543210987654326(const std::wstring& processPath)
{
    WINTRUST_FILE_INFO fileData;
    memset(&fileData, 0, sizeof(fileData));
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = processPath.c_str();

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData;
    memset(&winTrustData, 0, sizeof(winTrustData));
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(NULL, &policyGUID, &winTrustData);
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    return (status == ERROR_SUCCESS);
}

bool sub_9876543210987654327(const std::wstring& processName, const std::wstring& processPath)
{
    static const std::vector<std::wstring> safePaths = {
        L"C:\\Program Files\\",
        L"C:\\Program Files (x86)\\",
     };

    // Check if the processPath starts with any of the safe paths
    auto isSafePath = std::any_of(safePaths.begin(), safePaths.end(),
        [&processPath](const std::wstring& safePath) {
            return _wcsnicmp(processPath.c_str(), safePath.c_str(), safePath.length()) == 0;
        });

    if (isSafePath)
    {
        return true;  
    }

     if (!sub_9876543210987654326(processPath))
    {
        std::wstring message = L"Unsigned application ran: " + processName + L" at " + processPath;
        std::string u_11223(message.begin(), message.end());

         sub_78658698274623(u_11223, FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
        sub_519358913581358(u_11223);

        return false;
    }

    return true;
}


void sub_9876543210987654328()
{
    HANDLE u_12345 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (u_12345 == INVALID_HANDLE_VALUE)
    {
        sub_78658698274623("Failed to create process snapshot for unsigned application scan.", FOREGROUND_RED | FOREGROUND_INTENSITY);
        sub_519358913581358("Failed to create process snapshot for unsigned application scan.");
        return;
    }

    PROCESSENTRY32 u_112233;
    u_112233.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(u_12345, &u_112233))
    {
        do
        {
            wchar_t processPath[MAX_PATH];
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, u_112233.th32ProcessID);
            if (hProcess)
            {
                if (GetModuleFileNameEx(hProcess, NULL, processPath, sizeof(processPath) / sizeof(wchar_t)))
                {
                    sub_9876543210987654327(u_112233.szExeFile, processPath);
                }
                CloseHandle(hProcess);
            }
        } while (Process32Next(u_12345, &u_112233));
    }

    CloseHandle(u_12345);
}

void sub_9876543210987654329()
{
    HWND hwnd = GetTopWindow(NULL);
    while (hwnd != NULL)
    {
        wchar_t className[256];
        GetClassName(hwnd, className, sizeof(className) / sizeof(wchar_t));

        if (std::wstring(className) == L"Overlay")
        {
            std::wstring message = L"Warning: Detected overlay window: " + std::wstring(className);
            std::string u_11223(message.begin(), message.end());
            sub_78658698274623(u_11223, FOREGROUND_RED | FOREGROUND_INTENSITY);
            sub_519358913581358(u_11223);
        }

        hwnd = GetNextWindow(hwnd, GW_HWNDNEXT);
    }
}

void sub_9876543210987654330()
{
    DWORD procID = 0;
    HWND hwnd = FindWindow(NULL, L"FiveM");
    if (hwnd)
    {
        GetWindowThreadProcessId(hwnd, &procID);
    }

    if (procID == 0)
    {
        sub_78658698274623("FiveM.exe not found.", FOREGROUND_RED | FOREGROUND_INTENSITY);
        sub_519358913581358("FiveM.exe not found.");
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procID);
    if (!hProcess)
    {
        sub_78658698274623("Failed to open FiveM.exe process.", FOREGROUND_RED | FOREGROUND_INTENSITY);
        sub_519358913581358("Failed to open FiveM.exe process.");
        return;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
            {
                std::wstring moduleName(szModName);
                if (moduleName.find(L".dll") != std::wstring::npos && moduleName.find(L"FiveM") == std::wstring::npos)
                {
                    std::wstring message = L"Warning: Detected injected DLL in FiveM.exe: " + moduleName;
                    std::string u_11223(message.begin(), message.end());
                    sub_78658698274623(u_11223, FOREGROUND_RED | FOREGROUND_INTENSITY);
                    sub_519358913581358(u_11223);
                }
            }
        }
    }

    CloseHandle(hProcess);
}

void sub_9876543210987654331()
{
    std::vector<std::wstring> regPaths = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"System\\CurrentControlSet\\Services",
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
    };

    for (const auto& regPath : regPaths)
    {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            sub_78658698274623("Warning: Detected suspicious registry modification in " + std::string(regPath.begin(), regPath.end()), FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
            sub_519358913581358("Warning: Detected suspicious registry modification in " + std::string(regPath.begin(), regPath.end()));
            RegCloseKey(hKey);
        }
    }
}

void sub_9876543210987654332()
{
    std::vector<std::wstring> folders = {
        L"C:\\Windows\\Prefetch",
        L"C:\\Windows\\System32\\LogFiles",
        L"C:\\Windows\\System32\\drivers\\etc",
        L"C:\\Windows\\Temp",
        L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu",
        L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        L"C:\\Users\\Public\\Desktop",
        L"C:\\Windows\\System32\\Tasks",
        L"C:\\Windows\\System32\\drivers",
        L"C:\\Windows\\System32\\config\\systemprofile",
        L"C:\\Windows\\System32\\FxsTmp",
        L"C:\\Windows\\System32\\spool",
        L"C:\\Windows\\System32\\spool\\PRINTERS",
        L"C:\\Windows\\System32\\FxsTmp",
        L"C:\\Windows\\Logs",
        L"C:\\Windows\\ServiceProfiles\\LocalService",
        L"C:\\Windows\\ServiceProfiles\\NetworkService",
        L"C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local",
        L"C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\LocalLow",
        L"C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Roaming",
    };

    for (const auto& folder : folders)
    {
        HANDLE hDir = CreateFile(
            folder.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

        if (hDir == INVALID_HANDLE_VALUE)
        {
            std::wstring message = L"Warning: Folder locked or inaccessible: " + folder;
            std::string u_11223(message.begin(), message.end());
            sub_78658698274623(u_11223, FOREGROUND_RED | FOREGROUND_INTENSITY);
            sub_519358913581358(u_11223);
        }
        else
        {
            CloseHandle(hDir);
        }
    }
}

void sub_9876543210987654334()
{
    EVT_HANDLE hEventLog = EvtQuery(NULL, L"Application", L"*", EvtQueryReverseDirection | EvtQueryTolerateQueryErrors);
    if (hEventLog == NULL)
    {
        sub_78658698274623("Failed to query event log.", FOREGROUND_RED | FOREGROUND_INTENSITY);
        return;
    }

    EVT_HANDLE hEvent;
    DWORD dwBufferSize = 0, dwBufferUsed = 0;
    EVT_VARIANT* pRenderedValues = NULL;
    DWORD dwPropertyCount = 0;

    while (EvtNext(hEventLog, 1, &hEvent, INFINITE, 0, &dwBufferSize))
    {
        EvtRender(NULL, hEvent, EvtRenderEventValues, dwBufferUsed, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
        std::wstring providerName = pRenderedValues[EvtSystemProviderName].StringVal;

        if (providerName == L"SuspiciousApp")
        {
            sub_78658698274623("Warning: Suspicious event log detected from " + std::string(providerName.begin(), providerName.end()), FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
            sub_519358913581358("Warning: Suspicious event log detected from " + std::string(providerName.begin(), providerName.end()));
        }

        EvtClose(hEvent);
    }

    EvtClose(hEventLog);
}



void SetConsoleTextGreen() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}

void SetConsoleTextRed() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
}
void sub_9876543210987654335() {
    HRESULT hr;
    IWbemLocator* pLocator = nullptr;
    IWbemServices* pServices = nullptr;
    IEnumWbemClassObject* pEnumerator = nullptr;

    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) return;

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr)) return;

    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLocator);
    if (FAILED(hr)) return;

    hr = pLocator->ConnectServer(_bstr_t(L"ROOT\\SecurityCenter2"), NULL, NULL, 0, NULL, 0, 0, &pServices);
    if (FAILED(hr)) return;

    hr = pServices->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM AntiVirusProduct"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hr)) return;

    IWbemClassObject* pClassObject = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);

        if (uReturn == 0) {
            break;
        }

        VARIANT vtProp;
        hr = pClassObject->Get(L"displayName", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            VARIANT vtState;
            hr = pClassObject->Get(L"productState", 0, &vtState, 0, 0);
            if (SUCCEEDED(hr)) {
                if ((vtState.uintVal & 0x1000) == 0) {
                    SetConsoleTextRed();
                    std::wcout << L"Windows Defender or AV Product (DISABLED): " << vtProp.bstrVal << std::endl;
                }
                else {
                    SetConsoleTextGreen();
                    std::wcout << L"Windows Defender or AV Product (ACTIVE): " << vtProp.bstrVal << std::endl;
                }
                VariantClear(&vtState);
            }
        }
        VariantClear(&vtProp);
        pClassObject->Release();
    }

    pLocator->Release();
    pServices->Release();
    pEnumerator->Release();
    CoUninitialize();
}

void PrintMessage(const string& message, WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
    cout << message << endl;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void LogMessage(const string& message) {
     cout << "[LOG]: " << message << endl;
}

bool AnalyzeNTFSMetadata(const wstring& volume) {
    HANDLE volumeHandle = CreateFileW(volume.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (volumeHandle == INVALID_HANDLE_VALUE) {
        PrintMessage("[Aethers Scanner] Unable to open volume for NTFS metadata analysis.", FOREGROUND_RED | FOREGROUND_INTENSITY);
        LogMessage("Unable to open volume for NTFS metadata analysis.");
        return false;
    }

    DWORD bytesReturned;
    NTFS_VOLUME_DATA_BUFFER volumeData;

    if (!DeviceIoControl(volumeHandle, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &volumeData, sizeof(volumeData), &bytesReturned, NULL)) {
        CloseHandle(volumeHandle);
        PrintMessage("Unable to retrieve NTFS volume data.", FOREGROUND_RED | FOREGROUND_INTENSITY);
        LogMessage("Unable to retrieve NTFS volume data.");
        return false;
    }

    const wchar_t* ntfsMetadataFiles[] = { L"\\$LogFile", L"\\$J", L"\\$MFT", L"\\$Secure" };

    for (const auto& file : ntfsMetadataFiles) {
        wstring path = volume + file;
        HANDLE fileHandle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (fileHandle == INVALID_HANDLE_VALUE) {
            PrintMessage("Unable to open NTFS metadata file: " + string(file, file + wcslen(file)), FOREGROUND_RED | FOREGROUND_INTENSITY);
            LogMessage("Unable to open NTFS metadata file: " + string(file, file + wcslen(file)));
            continue;
        }
        else {
            PrintMessage("NTFS metadata file accessed: " + string(file, file + wcslen(file)), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            LogMessage("NTFS metadata file accessed: " + string(file, file + wcslen(file)));
        }
        CloseHandle(fileHandle);
    }

    CloseHandle(volumeHandle);
    return true;
}


void ResetConsoleText() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}
bool IsServiceRunning(const std::wstring& serviceName) {
    SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        return false;
    }

    SC_HANDLE hService = OpenService(hSCManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return false;
    }

    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    bool isRunning = false;

    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        isRunning = (status.dwCurrentState == SERVICE_RUNNING);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return isRunning;
}

bool HasServiceRestarted(const std::wstring& serviceName) {
    SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        return false;
    }

    SC_HANDLE hService = OpenService(hSCManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return false;
    }

    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    bool hasRestarted = false;

    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        ULONGLONG bootTime = 0;
        ULONGLONG serviceStartTime = 0;

        FILETIME ftBoot;
        ULONGLONG uptime = GetTickCount64() * 10000ULL;
        GetSystemTimeAsFileTime(&ftBoot);

        ULARGE_INTEGER bootTimeLI;
        bootTimeLI.HighPart = ftBoot.dwHighDateTime;
        bootTimeLI.LowPart = ftBoot.dwLowDateTime;
        bootTime = bootTimeLI.QuadPart - uptime;

        serviceStartTime = static_cast<ULONGLONG>(status.dwProcessId); 

        hasRestarted = (serviceStartTime > bootTime);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return hasRestarted;
}

void SearchExeFiles(const wstring& directory) {
    WIN32_FIND_DATAW findData;
    HANDLE findHandle = FindFirstFileW((directory + L"\\*.exe").c_str(), &findData);

    if (findHandle == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        const wstring fileName(findData.cFileName);

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (fileName != L"." && fileName != L"..") {
                SearchExeFiles(directory + L"\\" + fileName);
            }
        }
        else {
            wstring message = L"Executable found: " + directory + L"\\" + fileName;
            string logMessage(message.begin(), message.end());
            PrintMessage(logMessage, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            LogMessage(logMessage);
        }
    } while (FindNextFileW(findHandle, &findData) != 0);

    FindClose(findHandle);
}
#define BUFFER_SIZE 65536  // Increased buffer size to handle large amounts of data

void readUSNJournal(HANDLE volumeHandle, std::vector<std::wstring>& recentExecutables)
{
    DWORD bytesReturned;
    char* buffer = new char[BUFFER_SIZE];
    USN_JOURNAL_DATA_V0 journalData;

    // Query USN Journal data
    if (!DeviceIoControl(volumeHandle, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &journalData, sizeof(journalData), &bytesReturned, NULL))
    {
        std::cerr << "Failed to query USN journal. Error: " << GetLastError() << std::endl;
        delete[] buffer;
        return;
    }

    MFT_ENUM_DATA_V0 mftEnumData = { 0 };
    mftEnumData.StartFileReferenceNumber = 0;
    mftEnumData.LowUsn = 0;
    mftEnumData.HighUsn = journalData.NextUsn;

     while (true)
    {
        if (!DeviceIoControl(volumeHandle, FSCTL_ENUM_USN_DATA, &mftEnumData, sizeof(mftEnumData), buffer, BUFFER_SIZE, &bytesReturned, NULL))
        {
            if (GetLastError() == ERROR_HANDLE_EOF)
            {
                break;
            }
            else
            {
                std::cerr << "Failed to enumerate USN journal. Error: " << GetLastError() << std::endl;
                delete[] buffer;
                return;
            }
        }

        PUSN_RECORD usnRecord = (PUSN_RECORD)(buffer + sizeof(USN));
        while ((char*)usnRecord < buffer + bytesReturned)
        {
            if (usnRecord->FileNameLength > 0)
            {
                std::wstring fileName(usnRecord->FileName, usnRecord->FileNameLength / sizeof(WCHAR));

                 if (fileName.find(L".exe") != std::wstring::npos)
                {
                    recentExecutables.push_back(fileName);
                    if (recentExecutables.size() >= 10) {
                        delete[] buffer;
                        return;
                    }
                }
            }

            usnRecord = (PUSN_RECORD)((char*)usnRecord + usnRecord->RecordLength);
        }
    }

    delete[] buffer;
}
bool searchForStrings(const std::vector<std::string>& sectorData, const std::vector<std::string>& searchStrings)
{
    for (const auto& sector : sectorData)
    {
        for (const auto& searchString : searchStrings)
        {
            if (sector.find(searchString) != std::string::npos)
            {
                std::cout << "[Aethers Scanner] Found: " << searchString << std::endl;
                return true;
            }
        }
    }
    return false;
}

void pcasvc() {
    if (!SetDebugPrivileges())
    {
        wprintf(L"Failed to set SeDebugPrivilege. Some operations may fail.\n");
    }

    ACCESS_MASK desiredAccess = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == NULL)
    {
        wprintf(L"Failed to open driver. Exiting.\n");
    }

    std::wstring target_cmdline = L" -k LocalSystemNetworkRestricted -p -s PcaSvc";

    std::vector<DWORD> svchost_pids = get_svchost_process_ids_by_cmdline(target_cmdline);
    if (svchost_pids.empty()) {
        std::cout << "[Aethers Scanner] THE SERVICE HAS BEEN CLOSED/ALTERCATED, CHECK USER WITH PROCESS HACKER! [PcaSvc]" << std::endl;
    }
    else {
        for (DWORD pid : svchost_pids) {
             std::vector<std::string> strings_taho_clean = {
                "skript.gg",
                "skript.gg0Y0",
     
                "keyauth.win",
                "!!winhlp64.exe!2023 / 12 / 13:20 : 14 : 01!0!",
                "winhlp64.exe",
                "!!d3dconfig.exe!2023 / 12 / 13:20 : 14 : 01!0!",
                "d3dconfig.exe",
                "!d3dconfig",
                "!!d3dconfig",
                "d3dconfig",
                "api.tzproject.com",
                "tzproject.com",
                "0X16AD000",
                "0x164000",
                "0x2e09000",
                "0xd0a000",
                "0x4d4000",
                "0x35e000",
                "0xc1000c",
                "0x1256000",
                "0xd7000",
                "0xfe000",
                "0x1196000",
                "0x16b2000",
                "0x1437000",
                "0x1ad5000",
                "0x126000",
                "0x1c6000",
                "0x4b000",
                "0x231b000",
                "0x235f000",
                "0x2382000",
                "0x1c1000",
                "0x21f000",
                "GFSDK_TXAA.win64.bat",
                "0x6b808d",
                "0x2be000",
                "0xc1000c",
                "0x2ea6000",
                "0x559016",
                "0x9fe000",
                "0x404000",
                "0x1d7b000",
                "0x202b000",
                "0x73c8000",
                "0x18f000",
                "0x845000",
                "0x81f000",
                "0x42000",
                "0x1074000",
                "0x18f1000",
                "0x244000",
                "0x9c000",
                "0xa8a000",
                "0x5590ed",
                "0xb21000",
                "0x164000",
                "0xcab000",
                "0x41c000",
                "0xde000",
                "0X16AD000",
                "0xa15000",
                "2022/12/15:08:12:50",
                "0x3c0ad",
                "2081/08/19:04:22:55",
                "0x5590cf",
                "2095/10/17:16:06:32",
                "0x9e1000",
                "0x1138000",
                "0xef6000",
                "0x28e5000",
                "0x559069",
                "2022/03/29:14:24:50",
                "0x29a4000",
                "0xe19000",
                "0x5590a9",
                "0xe1a000",
                "0x2162000",
                "0xc70000",
                "0x8600",
                "0x135000",
                "0xb61000",
                "0x5e7000",
                "0x1081000",
                "0xf0000",
                "0xd32000",
                "0x231b000",
                "0x235f000",
                "0x2382000",
                "0x1c1000",
                "0x21f000",
                "0x6b808d",
                "0x2ea6000",
                "0x559016",
                "0x141000",
                "0X16AD000",
                "0x5590eb",
                "0x559048",
                "0x216000",
                "0x5590f9",
                "0xd32000",
                "0x94a000"
            };


            HANDLE hCacaasd = AethersOpenProcess(hDevice, pid, desiredAccess, hCacaasd);

            StringCleaner ahrsawaw(pid, strings_taho_clean);
            ahrsawaw.findStrings(hCacaasd);


            CloseHandle(hCacaasd);
        }
    }
}

void discord() {
    if (!SetDebugPrivileges())
    {
        wprintf(L"Failed to set SeDebugPrivilege. Some operations may fail.\n");
    }


    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == NULL)
    {
        wprintf(L"Failed to open driver. Exiting.\n");
    }

    std::wstring processName = L"discord.exe";
    DWORD pidsa = GetProcessIdByName(processName);
    if (pidsa == 0)
    {
        wprintf(L"Process discord.exe not found or access denied.\n");
    }


    HANDLE hProcess = NULL;
    ACCESS_MASK desiredAccess = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

    if (AethersOpenProcess(hDevice, pidsa, desiredAccess, hProcess))
    {
        StringCleaner sc(pidsa, {
     "1169648197245878282",
     "978030904679207012",
     "1191531786757492766",
     "1124070096378265620",
     "1116161366684881010",
     "1228793567972167820",
     "1144027946298917025",
     "820848124876685343",
     "1252604547113947219",
     "1106570727156625468",
     "1218886375307218964",
     "https://discord.gg/redengine",
     "https://discord.gg/GJh8p8edtD",
     "https://discord.gg/abso",
     "https://discord.gg/vortexmenu",
     "https://discord.gg/4N5f3VxS9b",
     "https://discord.gg/kVWKBhKRR7",
     "https://discord.gg/hxsoftwares",
     "https://discord.gg/tzproject",
     "https://discord.gg/9E3f2M92UN",
     "https://discord.gg/susano",
     "https://discord.gg/MwyUWh5",
     "https://discord.gg/rosereselling",
     "https://discord.gg/XRyGFjq58E",
     "https://discord.gg/E3TjAwdGX3",
     "https://discord.gg/38-stuff",
     "https://discord.gg/808reselling",
     "https://discord.gg/nineselling",
     "https://discord.gg/azzaro",
     "https://discord.gg/gEbuB2UaeP",
     "https://discord.gg/prestige-service",
     "https://discord.gg/ninereselling",
     "https://discord.gg/fD5FeBjRRW",
     "https://discord.gg/veax",
     "https://discord.gg/flyside",
     "https://discord.gg/sylace",
     "https://discord.gg/xyz-services",
     "https://discord.gg/tgmodz",
     "https://discord.gg/testogg",
     "https://discord.gg/gosth",
     "https://discord.gg/dmtmarket",
     "https://discord.gg/alchemistservices",
     "https://discord.gg/hopeselling",
     "https://discord.gg/masewstore",
     "https://discord.gg/kN2KaEhTUJ",
     "https://discord.gg/999selling",
     "https://discord.gg/420service",
     "https://discord.gg/nc4UfRWHC3",
     "https://discord.gg/ribbonstore",
     "https://discord.gg/r56",
     "https://discord.gg/fivexx",
     "https://discord.gg/mdshop",
     "https://discord.gg/safemarkt",
     "https://discord.gg/uzui",
     "https://discord.gg/lmarket",
     "886463810142093362",
     "1028676617242939422",
     "886931514829467648",
     "935954241300885556",
     "880603004301111336",
     "957382222439153694",
     "934520444604784640",
     "881331329403326504",
     "975836953742290994",
     "959048432172015696",
     "994388555625398333",
     "815331538656034816",
     "829222617356566549",
     "946329417968386098",
     "971129443865227284",
     "899785629523660881",
     "1001624044224921651",
     "https://discord.gg/jibbitfvm",
     "https://discord.gg/astrarip",
     "1001114918092816384",
     "955958093890605067"
            });


        sc.findStrings(hProcess);


    }
    else
    {
        wprintf(L"Failed to open process lsass.exe.\n");
    }

}
void searchindexer() {
    if (!SetDebugPrivileges())
    {
        wprintf(L"Failed to set SeDebugPrivilege. Some operations may fail.\n");
    }


    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == NULL)
    {
        wprintf(L"Failed to open driver. Exiting.\n");
    }

    std::wstring processName = L"SearchIndexer.exe";
    DWORD pidsa = GetProcessIdByName(processName);
    if (pidsa == 0)
    {
        wprintf(L"Process SearchIndexer.exe not found or access denied.\n");
    }

 
    HANDLE hProcess = NULL;
    ACCESS_MASK desiredAccess = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

    if (AethersOpenProcess(hDevice, pidsa, desiredAccess, hProcess))
    {
        StringCleaner sc(pidsa, {
 
            "skript.gg",
            "keyauth.cc",
            "keyauth.win",
            "shey.tech",
            "pedrin.cc",
            "projectcheats.com",
            "skript.gg/support",
            "visualsettings.bat",
            "tzproject.com",
            "api.tzproject.com",
            "2024/01/20:11:56:54"
            });

        sc.findStrings(hProcess);


    }
    else
    {
        wprintf(L"Failed to open process lsass.exe.\n");
    }

}
void clipboard() {
    if (!SetDebugPrivileges())
    {
        wprintf(L"Failed to set SeDebugPrivilege. Some operations may fail.\n");
    }

    ACCESS_MASK desiredAccess = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == NULL)
    {
        wprintf(L"Failed to open driver. Exiting.\n");
    }
    std::wstring target_cmdline = L"-k ClipboardSvcGroup -p -s cbdhsvc";

    std::vector<DWORD> svchost_pids = get_svchost_process_ids_by_cmdline(target_cmdline);

    if (svchost_pids.empty()) {
        std::cout << "[Aethers Scanner] THE SERVICE HAS BEEN CLOSED/ALTERCATED, CHECK USER WITH PROCESS HACKER!" << std::endl;
    }
    else {
        for (DWORD pid : svchost_pids) {
            std::vector<std::string> strings_taho_clean = {
               "skript.gg",
               "skript.gg0Y0",
    "tzproject",
               "keyauth.win",
               "!!winhlp64.exe!2023 / 12 / 13:20 : 14 : 01!0!",
               "winhlp64.exe",
               "!!d3dconfig.exe!2023 / 12 / 13:20 : 14 : 01!0!",
               "d3dconfig.exe",
               "!d3dconfig",
               "!!d3dconfig",
               "d3dconfig",
               "api.tzproject.com",
               "tzproject.com",
               "2024/01/20:11:56:54"
            };


            HANDLE hCacaasd = AethersOpenProcess(hDevice, pid, desiredAccess, hCacaasd);

            StringCleaner ahrsawaw(pid, strings_taho_clean);
            ahrsawaw.findStrings(hCacaasd);


            CloseHandle(hCacaasd);
        }
    }
}


void UnistackSvcGroup() {
    if (!SetDebugPrivileges())
    {
        wprintf(L"Failed to set SeDebugPrivilege. Some operations may fail.\n");
    }

    ACCESS_MASK desiredAccess = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == NULL)
    {
        wprintf(L"Failed to open driver. Exiting.\n");
    }
    std::wstring target_cmdline = L" -k UnistackSvcGroup -s CDPUserSvc";

    std::vector<DWORD> svchost_pids = get_svchost_process_ids_by_cmdline(target_cmdline);

    if (svchost_pids.empty()) {
        std::cout << "[Aethers Scanner] THE SERVICE HAS BEEN CLOSED/ALTERCATED, CHECK USER WITH PROCESS HACKER!" << std::endl;
    }
    else {
        for (DWORD pid : svchost_pids) {
            std::vector<std::string> strings_taho_clean = {
               "skript.gg",
               "skript.gg0Y0",
    "tzproject",
               "keyauth.win",
               "!!winhlp64.exe!2023 / 12 / 13:20 : 14 : 01!0!",
               "winhlp64.exe",
               "!!d3dconfig.exe!2023 / 12 / 13:20 : 14 : 01!0!",
               "d3dconfig.exe",
               "!d3dconfig",
               "!!d3dconfig",
               "d3dconfig",
               "api.tzproject.com",
               "tzproject.com",
               "2024/01/20:11:56:54"
            };


            HANDLE hCacaasd = AethersOpenProcess(hDevice, pid, desiredAccess, hCacaasd);

            StringCleaner ahrsawaw(pid, strings_taho_clean);
            ahrsawaw.findStrings(hCacaasd);


            CloseHandle(hCacaasd);
        }
    }
}

void WinHttpAutoProxySvc() {
    if (!SetDebugPrivileges())
    {
        wprintf(L"Failed to set SeDebugPrivilege. Some operations may fail.\n");
    }

    ACCESS_MASK desiredAccess = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == NULL)
    {
        wprintf(L"Failed to open driver. Exiting.\n");
    }
    std::wstring target_cmdline = L"  -k LocalServiceNetworkRestricted -p -s WinHttpAutoProxySvc";

    std::vector<DWORD> svchost_pids = get_svchost_process_ids_by_cmdline(target_cmdline);

    if (svchost_pids.empty()) {
        std::cout << "[Aethers Scanner] THE SERVICE HAS BEEN CLOSED/ALTERCATED, CHECK USER WITH PROCESS HACKER!" << std::endl;
    }
    else {
        for (DWORD pid : svchost_pids) {
            std::vector<std::string> strings_taho_clean = {
               "skript.gg",
               "skript.gg0Y0",
    "tzproject",
               "keyauth.win",
               "!!winhlp64.exe!2023 / 12 / 13:20 : 14 : 01!0!",
               "winhlp64.exe",
               "!!d3dconfig.exe!2023 / 12 / 13:20 : 14 : 01!0!",
               "d3dconfig.exe",
               "!d3dconfig",
               "!!d3dconfig",
               "d3dconfig",
               "api.tzproject.com",
               "tzproject.com",
               "2024/01/20:11:56:54"
            };


            HANDLE hCacaasd = AethersOpenProcess(hDevice, pid, desiredAccess, hCacaasd);

            StringCleaner ahrsawaw(pid, strings_taho_clean);
            ahrsawaw.findStrings(hCacaasd);


            CloseHandle(hCacaasd);
        }
    }
}

void explorer() {
    if (!SetDebugPrivileges())
    {
        wprintf(L"Failed to set SeDebugPrivilege. Some operations may fail.\n");
    }


    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == NULL)
    {
        wprintf(L"Failed to open driver. Exiting.\n");
    }

    std::wstring processName = L"explorer.exe";
    DWORD pidsa = GetProcessIdByName(processName);
    if (pidsa == 0)
    {
        wprintf(L"Process explorer.exe not found or access denied.\n");
    }


    HANDLE hProcess = NULL;
    ACCESS_MASK desiredAccess = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

    if (AethersOpenProcess(hDevice, pidsa, desiredAccess, hProcess))
    {
        StringCleaner sc(pidsa, {
       "skript.gg",
      "keyauth.cc",
      "keyauth.win",
      "shey.tech",
      "pedrin.cc",
      "projectcheats.com",
      "skript.gg/support",
      "visualsettings.bat",
      "tzproject.com",
      "api.tzproject.com",
      "2024/01/20:11:56:54",
      "x64a.rpf",
      "imdisk0",
      "imgui.ini",
      "importopti.py",
      "ZC-loadout",
      "loader.vmp",
      "settings.cock",
      "file:///A",
      "file:///B",
      "file:///F",
      "file:///G",
      "file:///H",
      "file:///I",
      "file:///J",
      "file:///K",
      "file:///L",
      "file:///M",
      "loader.cfg",
      "menyoLog.txt",
      "Boot.sdi",
      "file:///N",
      "file:///Q",
      "file:///P",
      "file:///O",
      "file:///R",
      "file:///S",
      "file:///T",
      "file:///U",
      "file:///V",
      "file:///W",
      "file:///X",
      "file:///Y",
      "file:///Z",
      "java64.dll",
      "gdx-freetype64.dll",
      "lwjgl.dll",
      "hsperfdata",
      "IMGUI",
      ".dll.x",
      "FXSEXT.exe",
      "abc.abc",
      "PsExec.exe",
      "procdump.exe",
      "Osfmount",
      "cfg.latest",
      "favorites.cfg",
      "CZltWMtLL5xBgZ2M",
      "IMJJPUEX.EXE",
      "bleachbit.exe",
      "purity.exe",
      "RWClean.exe",
      "J:\\svchost.exe",
      "wvpci.exe",
      "AMDE34B.DAT",
      "appmgts.exe",
      "appmgmts.exe",
      "AppCrash_appmgmts.exe"
            });


        sc.findStrings(hProcess);


    }
    else
    {
        wprintf(L"Failed to open process lsass.exe.\n");
    }

}

 
 
 
#include <Windows.h>

 

#include <wininet.h>
#pragma comment(lib, "wininet.lib")
std::string base64_decode(const std::string& encoded) {
    static constexpr unsigned char kDecodingTable[] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
        64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
        64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
    };

    size_t in_len = encoded.size();
    if (in_len % 4 != 0) return "";
    size_t out_len = in_len / 4 * 3;
    if (encoded[in_len - 1] == '=') out_len--;
    if (encoded[in_len - 2] == '=') out_len--;

    std::string decoded;
    decoded.reserve(out_len);

    for (size_t i = 0; i < in_len;) {
        unsigned int sextet_a = encoded[i] == '=' ? 0 & i++ : kDecodingTable[encoded[i++]];
        unsigned int sextet_b = encoded[i] == '=' ? 0 & i++ : kDecodingTable[encoded[i++]];
        unsigned int sextet_c = encoded[i] == '=' ? 0 & i++ : kDecodingTable[encoded[i++]];
        unsigned int sextet_d = encoded[i] == '=' ? 0 & i++ : kDecodingTable[encoded[i++]];

        unsigned int triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

        if (i < out_len) decoded.push_back((triple >> 2 * 8) & 0xFF);
        if (i < out_len) decoded.push_back((triple >> 1 * 8) & 0xFF);
        if (i < out_len) decoded.push_back((triple >> 0 * 8) & 0xFF);
    }

    return decoded;
}

std::string decryptResponse(const std::string& encryptedData) {
    
    std::string decrypted;
    int key = 128;
    size_t saltLength = 8;
    if (encryptedData.size() < saltLength) {
        return decrypted;
    }
    std::string salt = encryptedData.substr(0, saltLength);

    for (size_t i = saltLength; i < encryptedData.size(); ++i) {
        char transformed = encryptedData[i];
        char original = (transformed - (((key << 3) & 0xFF) + salt[i % saltLength])) ^ key;
        decrypted.push_back(original);
        key = ((key * 5) + salt[i % saltLength]) % 256;
    }

    return decrypted;
}

#include <sstream>

#define OBFUSHEADER_H

// TODO: find a better way to do this
#define true 1
#define false 0

// Obfusheader settings

// Possible values - THREADLOCAL, NORMAL
// Threadlocal encryption stores the data inside threadlocal space. This can sometimes prevent the compiler from optimizing it away + makes it harder to extract the data
// Normal encryption mode is more performant and stable but a bit less secure
#define ENCRYPT_MODE THREADLOCAL

// Possible values - STATIC, DYNAMIC
// Static call hider stores the function pointers inside a static storager (.data section basically) which is very optimized
// Dynamic call hider inits function pointer arrays in runtime 
#define CALL_HIDE_MODE DYNAMIC

// Possible values - true/false
// Force inline is recommended for better performance and makes it a lot harder to reverse-engineer
#define FORCE_INLINE true

// Possible values true/false
// Control flow affect the performance in a negative way (but not very much)
// It creates garbage flow branches to made the decryption hidden among them
#define CONTROL_FLOW true

// Without forceinline the compiler will mostly ignore inline methods
#if FORCE_INLINE == true
#if defined(_MSC_VER) && !defined(__clang__) 
#define INLINE __forceinline // Visual C++
#else
#define INLINE __attribute__((always_inline)) inline // GCC/G++/CLANG
#endif
#else
#define INLINE inline // Regular inline doesn't always inline
#endif

// __TIME__ && __COUNTER__ both used as a random provider (compile-time) (XX:XX:XX)
#define CTimeSeed ((__COUNTER__ +  __TIME__[0] + __TIME__[1] + __TIME__[3] + __TIME__[4] +\
                                   __TIME__[6] + __TIME__[7]) * 2654435761u)
#define RND(Min, Max) (Min + (CTimeSeed % (Max - Min + 1)))

// Normal & threadlocal modes
#define OBF_KEY_NORMAL(x, type, size, key) []() {\
    constexpr static auto data = obf::obfuscator<type, size, key>(x);\
    return data;\
}()
#define OBF_KEY_THREADLOCAL(x, type, size, key) []() -> obf::decryptor<type, size, key>& {\
    constexpr static auto data = obf::obfuscator<type, size, key>(x);\
    thread_local auto decryptor = obf::decryptor<type, size, key>(data);\
    return decryptor;\
}()
#define OBF_NORMAL(x) OBF_KEY_NORMAL(x, obf::clean_type<decltype(obf::gettype(x))>, obf::getsize(x), (char)RND(1, 255))
#define OBF_THREADLOCAL(x) OBF_KEY_THREADLOCAL(x, obf::clean_type<decltype(obf::gettype(x))>, obf::getsize(x), (char)RND(1, 255))

#if ENCRYPT_MODE == THREADLOCAL
#define OBF(x) (meta::decay_t<decltype(x)>) OBF_THREADLOCAL(x)
#else
#define OBF(x) (meta::decay_t<decltype(x)>) OBF_NORMAL(x)
#endif

// Pointer-based call hiding (Crossplatform)
#define DYNAMIC_HIDE_CALL(x, ...) ((decltype(x)) obf::ptr_hider<decltype(x), x, RND(0, 5)>().get())(__VA_ARGS__)
#define STATIC_HIDE_CALL(x, ...) ((decltype(x)) obf::static_storager<decltype(x), x>[OBF(5)])(__VA_ARGS__)
#if CALL_HIDE_MODE == STATIC
#define CALL(x, ...) STATIC_HIDE_CALL(x, __VA_ARGS__)
#elif CALL_HIDE_MODE == DYNAMIC
#define CALL(x, ...) DYNAMIC_HIDE_CALL(x, __VA_ARGS__)
#endif
// Symbol-based call hiding (different for Linux & windows)
#if defined(__linux__) || defined(__ANDROID__)
#include <dlfcn.h>
#define CALL_EXPORT(mtd, def) ((def)(dlsym(RTLD_DEFAULT, OBF(mtd))))
#elif _WIN32
#include <windows.h>
#include <conio.h>
#if defined(_MSC_VER) && !defined(__clang__) // in VisualC++ we cannot encrypt LPCWSTRs for now (ihate windows.h)
#define CALL_EXPORT(lib, mtd, def) ((def)(GetProcAddress(LoadLibrary(lib), mtd)))
#else
#define CALL_EXPORT(lib, mtd, def) ((def)(GetProcAddress(LoadLibrary(OBF(lib)), OBF(mtd))))
#endif
#endif

// Binary watermarking for IDA/GHIDRA that bypasses compiler optimizations
#define WATERMARK(...)\
    const char * data[] = {__VA_ARGS__};\
    for (volatile int i = 0; i < sizeof(data)/sizeof(data[0]); i++)\
        obf::obf_draw(data[i]);\



// This was created so the header works without type_traits (on gcc and other compilers)
// It basically replicates type_traits, it might look scary just skip it
namespace meta {

    template<class T, T v>
    struct integral_constant {
        static constexpr T value = v;
        using value_type = T;
        using type = integral_constant; // using injected-class-name
        constexpr operator value_type() const noexcept { return value; }
        constexpr value_type operator()() const noexcept { return value; } // since c++14
    };

    typedef integral_constant<bool, false> false_type;
    typedef integral_constant<bool, true> true_type;

    // primary template
    template<class>
    struct is_function : false_type {};

    // specialization for regular functions
    template<class Ret, class... Args>
    struct is_function<Ret(Args...)> : true_type {};

    // specialization for variadic functions such as std::printf
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...)> : true_type {};

    // specialization for function types that have cv-qualifiers
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) volatile> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const volatile> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) const> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) volatile> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) const volatile> : true_type {};

    // specialization for function types that have ref-qualifiers
    template<class Ret, class... Args>
    struct is_function<Ret(Args...)&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) volatile&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const volatile&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...)&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) const&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) volatile&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) const volatile&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...)&&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const&&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) volatile&&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const volatile&&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...)&&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) const&&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) volatile&&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) const volatile&&> : true_type {};

    template<class T>
    struct is_array : false_type {};
    template<class T>
    struct is_array<T[]> : true_type {};
    template<class T, size_t N>
    struct is_array<T[N]> : true_type {};

    template<class T>
    struct remove_extent { using type = T; };
    template<class T>
    struct remove_extent<T[]> { using type = T; };
    template<class T, size_t N>
    struct remove_extent<T[N]> { using type = T; };

    template<class T> struct remove_reference { typedef T type; };
    template<class T> struct remove_reference<T&> { typedef T type; };
    template<class T> struct remove_reference<T&&> { typedef T type; };

    template<class T> struct remove_cv { typedef T type; };
    template<class T> struct remove_cv<const T> { typedef T type; };
    template<class T> struct remove_cv<volatile T> { typedef T type; };
    template<class T> struct remove_cv<const volatile T> { typedef T type; };

    template<class T> struct remove_const { typedef T type; };
    template<class T> struct remove_const<const T> { typedef T type; };

    template<class T> struct remove_volatile { typedef T type; };
    template<class T> struct remove_volatile<volatile T> { typedef T type; };

    template<class T>
    struct remove_all_extents { typedef T type; };
    template<class T>
    struct remove_all_extents<T[]> {
        typedef typename remove_all_extents<T>::type type;
    };
    template<class T, size_t N>
    struct remove_all_extents<T[N]> {
        typedef typename remove_all_extents<T>::type type;
    };

    template<bool B, class T, class F>
    struct conditional { using type = T; };
    template<class T, class F>
    struct conditional<false, T, F> { using type = F; };

    template<class T>
    struct type_identity { using type = T; }; // or use std::type_identity (since C++20)
    template<class T>
    auto try_add_pointer(int) -> type_identity<typename remove_reference<T>::type*>;  // usual case
    template<class T>
    auto try_add_pointer(...) -> type_identity<T>;  // unusual case (cannot form std::remove_reference<T>::type*)
    template<class T>
    struct add_pointer : decltype(try_add_pointer<T>(0)) {};

    // Helpers from C++14 
    template<class T>
    using remove_cv_t = typename remove_cv<T>::type;
    template<class T>
    using remove_const_t = typename remove_const<T>::type;
    template<class T>
    using remove_volatile_t = typename remove_volatile<T>::type;
    template<class T>
    using remove_reference_t = typename remove_reference<T>::type;
    template<class T>
    using remove_all_extents_t = typename remove_all_extents<T>::type;

    template<class T>
    struct decay {
    private:
        typedef typename remove_reference<T>::type U;
    public:
        typedef typename conditional<
            is_array<U>::value,
            typename add_pointer<typename remove_extent<U>::type>::type,
            typename conditional<
            is_function<U>::value,
            typename add_pointer<U>::type,
            typename remove_cv<U>::type
            >::type
        >::type type;
    };

    template<class T>
    using decay_t = typename decay<T>::type;
}

namespace obf {

    template <class _Ty>
    using clean_type = typename meta::remove_const_t<meta::remove_reference_t<_Ty>>;

    template <typename T, T value>
    static T ensure_threadlocal() { thread_local T v = value; return v; }

    template <typename T, T value>
    static constexpr T ensure_constexpr() { return value; }

    template<typename T, int size>
    constexpr size_t getsize(const T(&)[size]) { return size; }

    template<typename T>
    constexpr size_t getsize(T) { return 1; }

    template<typename T, size_t size>
    constexpr static T gettype(const T(&)[size]);

    template<typename T>
    constexpr static T gettype(T);

    // Decryption with control flow to confuse IDA/GHIDRA
    template <class T, char key, size_t size>
    INLINE void xord(T* data, int* stack, int* value) {
#if CONTROL_FLOW == true
        for (int i = 0; i < size; i++) {
            goto l_1;

        l_increase:
            *stack += 1; // -Wunused-value

        l_1:
            if (*stack == *value + 1) {
                data[i] = data[i] ^ (*value + 1);
                goto l_increase;
            }
            if (*stack == *value + 2) {
                data[i] = data[i] ^ (*value + 2);
                goto l_increase;
            }
            if (*stack == *value + 0) {
                data[i] = data[i] ^ static_cast<T>(key + i); // real
                continue;
            }
            if (*stack == *value + 4) {
                data[i] = data[i] ^ (*value + 3);
                goto l_increase;
            }
            if (*stack == *value + 5) {
                data[i] = data[i] ^ (*value + 4);
                goto l_increase;
            }
        }
#else
        for (int i = 0; i < size; i++)
            data[i] = data[i] ^ static_cast<T>(key + i); // no CONTROL_FLOW (optimized)
#endif
    }

    template <class T, size_t size, char key>
    class obfuscator {
    public:
        INLINE constexpr obfuscator(const T* data) {
            for (int i = 0; i < size; i++)
                m_data[i] = data[i] ^ static_cast<T>(key + i);
        }

        INLINE constexpr obfuscator(const T data) {
            m_data[0] = data ^ key;
        }

        INLINE T* decrypt() {
            if (!decrypted) {
                xord<T, key, size>(m_data, &stack, &value);
            }
            decrypted = true;
            return m_data;
        }

        INLINE operator T* () {
            return decrypt();
        }

        INLINE operator T () {
            return decrypt()[0];
        }

        int stack = 0, value = 0;
        T result = NULL;

        bool decrypted = false;
        T m_data[size]{};
    };

    template <class T, size_t size, char key>
    class decryptor {
    public:
        INLINE decryptor(const obfuscator<T, size, key> data) {
            for (int i = 0; i < size; i++)
                m_data[i] = data.m_data[i];
        }

        INLINE T* decrypt() {
            if (!decrypted) {
                xord<T, key, size>(m_data, &stack, &value);
            }
            decrypted = true;
            return m_data;
        }

        INLINE operator T* () {
            return decrypt();
        }

        INLINE operator T () {
            return decrypt()[0];
        }

        int stack = 0, value = 0;
        T result = NULL;

        bool decrypted = false;
        T m_data[size]{};
    };

    volatile void obf_draw_orig(const char* param) { } // to avoid crashing we assign a real func
    typedef volatile void(*draw_ptr) (const char*); // define a draw function
    volatile draw_ptr obf_draw = reinterpret_cast<volatile void(*)(const char*)>(obf_draw_orig); // assign draw_orig to avoid segfault

    volatile void main_decoy() {
        // Message for crackers ;)
        WATERMARK("Stop reversing the program",
            "Reconsider your life choices",
            "And go touch some grass", "");
    }

    // Fake decoy functions to hide the original one (for call hiding)
    void decoy_1() { main_decoy(); }
    void decoy_2() { main_decoy(); }
    void decoy_3() { main_decoy(); }
    void decoy_4() { main_decoy(); }
    void decoy_5() { main_decoy(); }
    void decoy_6() { main_decoy(); }
    void decoy_7() { main_decoy(); }
    void decoy_8() { main_decoy(); }
    void decoy_9() { main_decoy(); }
    void decoy_10() { main_decoy(); }

    // We cannot randomize the real function index while using static storager sadly
    // So it's just a hardcoded index, for example 5 (like here)
    template <typename T, T real>
    T static_storager[] = {
        reinterpret_cast<T>(&decoy_1),
        reinterpret_cast<T>(&decoy_2),
        reinterpret_cast<T>(&decoy_3),
        reinterpret_cast<T>(&decoy_4),
        reinterpret_cast<T>(&decoy_5),
        reinterpret_cast<T>(real),
        reinterpret_cast<T>(&decoy_6),
        reinterpret_cast<T>(&decoy_7),
        reinterpret_cast<T>(&decoy_1),
        reinterpret_cast<T>(&decoy_2),
        reinterpret_cast<T>(&decoy_3),
        reinterpret_cast<T>(&decoy_4),
        reinterpret_cast<T>(&decoy_5),
        reinterpret_cast<T>(&decoy_1),
        reinterpret_cast<T>(&decoy_2),
        reinterpret_cast<T>(&decoy_3)
    };

    // In dynamic case we can actually randomize the index
    template <typename T, T real, int index>
    class ptr_hider {
    public:
        INLINE ptr_hider() {
            real_index = OBF(index);
        START:
            int storager_size = sizeof(storager) / sizeof(storager[0]);
            if (real_index >= 0 && real_index < storager_size) {
                storager[real_index] = real;
                goto END;
            }
            if (real_index + 1 >= 0 && real_index + 1 < storager_size) {
                storager[real_index + 1] = reinterpret_cast<T>(&decoy_1);
                goto START;
            }
            if (real_index + 2 >= 0 && real_index + 2 < storager_size) {
                storager[real_index + 2] = reinterpret_cast<T>(&decoy_2);
                goto END;
            }
            if (real_index + 2 >= 0 && real_index + 3 < storager_size) {
                storager[real_index + 3] = reinterpret_cast<T>(&decoy_3);
                goto START;
            }
            if (real_index + 2 >= 0 && real_index + 4 < storager_size) {
                storager[real_index + 4] = reinterpret_cast<T>(&decoy_4);
                goto END;
            }
            if (real_index + 2 >= 0 && real_index + 5 < storager_size) {
                storager[real_index + 5] = reinterpret_cast<T>(&decoy_5);
                goto START;
            }
        END: return;
        }

        T get() {
            return storager[real_index];
        }

        int real_index = 0;
        T storager[5];
    };
}

 
 void SetConsoleTextYellow() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}
 

int checkver() {
 

 

    HINTERNET hInternet = InternetOpen(xorstr_(L"Aethers"), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return 1;
    }

    HINTERNET hConnect = InternetOpenUrl(hInternet, xorstr_(L"https://aethers.cc/version.php"), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return 1;
    }

    char buffer[128];
    DWORD bytesRead;
    std::string readBuffer;

    while (InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead != 0) {
        buffer[bytesRead] = '\0';
        readBuffer.append(buffer, bytesRead);
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
     if (readBuffer != xorstr_("1.2")) {
        MessageBoxA(NULL, xorstr_("Please go to aethers.cc and update!"), xorstr_("Update Required"), MB_OK | MB_ICONINFORMATION);
        return 1;
    }

 
 

    return 0;
}

void ClearScreen() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD count, cellCount;
    COORD homeCoords = { 0, 0 };

    if (hConsole == INVALID_HANDLE_VALUE) return;
    if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) return;
    cellCount = csbi.dwSize.X * csbi.dwSize.Y;
    FillConsoleOutputCharacter(hConsole, (TCHAR)' ', cellCount, homeCoords, &count);
    FillConsoleOutputAttribute(hConsole, csbi.wAttributes, cellCount, homeCoords, &count);
    SetConsoleCursorPosition(hConsole, homeCoords);
}
void SearchNTFSJournalForVHD(const std::wstring& volume) {
    HANDLE hVolume = CreateFileW(volume.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hVolume == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[Aethers Scanner] Failed to open volume: " << volume << std::endl;
        return;
    }

    USN_JOURNAL_DATA journalData;
    DWORD bytesReturned;
    if (!DeviceIoControl(hVolume, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &journalData, sizeof(journalData), &bytesReturned, NULL)) {
        std::wcerr << L"[Aethers Scanner] Failed to query USN journal." << std::endl;
        CloseHandle(hVolume);
        return;
    }

    MFT_ENUM_DATA mftEnumData = { 0 };
    mftEnumData.StartFileReferenceNumber = 0;
    mftEnumData.LowUsn = 0;
    mftEnumData.HighUsn = journalData.NextUsn;

    BYTE buffer[4096];
    USN_RECORD* usnRecord;

    while (DeviceIoControl(hVolume, FSCTL_ENUM_USN_DATA, &mftEnumData, sizeof(mftEnumData), buffer, sizeof(buffer), &bytesReturned, NULL) && bytesReturned > 0) {
        BYTE* p = buffer;
        while (p < buffer + bytesReturned) {
            usnRecord = (USN_RECORD*)p;
            std::wstring fileName(usnRecord->FileName, usnRecord->FileNameLength / sizeof(WCHAR));
            if (fileName.find(L".vhd") != std::wstring::npos) {
                std::wcout << L"[Aethers Scanner] Found VHD file: " << fileName << std::endl;
            }
            p += usnRecord->RecordLength;
        }
    }

    CloseHandle(hVolume);
}

void CheckLoadedVHDs() {
    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            wchar_t driveLetter = L'A' + i;
            std::wstring drivePath = L"\\\\.\\";
            drivePath += driveLetter;
            drivePath += L":";

            std::wcout << L"[Aethers Scanner] Searching drive: " << drivePath << std::endl;
            SearchNTFSJournalForVHD(drivePath);
        }
    }
}
void SetConsoleTextReset() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 7);
}

void CheckMountedVHDs() {
    DWORD bufferSize = MAX_PATH;
    WCHAR buffer[MAX_PATH];

    HANDLE hFind = FindFirstVolume(buffer, bufferSize);
    if (hFind == INVALID_HANDLE_VALUE) {
        SetConsoleTextYellow();
        std::wcerr << L"[Aethers Scanner] Failed to find volumes." << std::endl;
        SetConsoleTextReset();
        return;
    }

    do {
        std::wstring volumeName = buffer;
        if (volumeName.find(L"\\\\?\\Volume{") != std::wstring::npos) {
            SetConsoleTextYellow();
            std::wcout << L"[Aethers Scanner] Possible bypass (deletion of Volume): " << volumeName << std::endl;
            SetConsoleTextReset();
        }
        UINT driveType = GetDriveType(volumeName.c_str());
        if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOTE) {
            std::wcout << L"[Aethers Scanner] Checking volume: " << volumeName << std::endl;
         }
    } while (FindNextVolume(hFind, buffer, bufferSize));

    FindVolumeClose(hFind);
}

void SearchNTFSJournalForDLL(const std::wstring& volume) {
    HANDLE hVolume = CreateFileW(volume.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hVolume == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[Aethers Scanner] Failed to open volume: " << volume << std::endl;
        return;
    }

    USN_JOURNAL_DATA journalData;
    DWORD bytesReturned;
    if (!DeviceIoControl(hVolume, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &journalData, sizeof(journalData), &bytesReturned, NULL)) {
        std::wcerr << L"[Aethers Scanner] Failed to query USN journal." << std::endl;
        CloseHandle(hVolume);
        return;
    }

    MFT_ENUM_DATA mftEnumData = { 0 };
    mftEnumData.StartFileReferenceNumber = 0;
    mftEnumData.LowUsn = 0;
    mftEnumData.HighUsn = journalData.NextUsn;

    BYTE buffer[4096];
    USN_RECORD* usnRecord;

    while (DeviceIoControl(hVolume, FSCTL_ENUM_USN_DATA, &mftEnumData, sizeof(mftEnumData), buffer, sizeof(buffer), &bytesReturned, NULL) && bytesReturned > 0) {
        BYTE* p = buffer;
        while (p < buffer + bytesReturned) {
            usnRecord = (USN_RECORD*)p;
            std::wstring fileName(usnRecord->FileName, usnRecord->FileNameLength / sizeof(WCHAR));
            if (fileName.find(L".dll") != std::wstring::npos) {
                std::wcout << L"[Aethers Scanner] Found DLL file: " << fileName << std::endl;
            }
            p += usnRecord->RecordLength;
        }
    }

    CloseHandle(hVolume);
}


void CheckOtherDrivesForDLLs() {
    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            wchar_t driveLetter = L'A' + i;
            std::wstring drivePath = L"\\\\.\\";
            drivePath += driveLetter;
            drivePath += L":";

                std::wcout << L"[Aethers Scanner] Searching drive: " << drivePath << std::endl;
                SearchNTFSJournalForDLL(drivePath);
            
        }
    }
}
void CheckUnusedSpace() {
    DWORD bufferSize = MAX_PATH;
    WCHAR buffer[MAX_PATH];

    HANDLE hFind = FindFirstVolume(buffer, bufferSize);
    if (hFind == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[Aethers Scanner] Failed to find volumes." << std::endl;
        return;
    }

    do {
        std::wstring volumeName = buffer;
        ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
        if (GetDiskFreeSpaceEx(volumeName.c_str(), &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
            if (totalNumberOfFreeBytes.QuadPart > (totalNumberOfBytes.QuadPart * 0.1)) {
                SetConsoleTextYellow();
                std::wcout << L"[Aethers Scanner] Warning: Unused space detected on volume: " << volumeName << std::endl;
                ResetConsoleText();
            }
        }
    } while (FindNextVolume(hFind, buffer, bufferSize));

    FindVolumeClose(hFind);
}
void SetConsoleRedText() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
}

void CheckEventViewerErrors() {
    EVT_HANDLE hResults = EvtQuery(NULL, L"Application", L"Level=2", EvtQueryChannelPath);
    if (!hResults) {
        cerr << "Failed to query event log." << endl;
        return;
    }

    DWORD returned = 0;
    EVT_HANDLE hEvent = NULL;
    while (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &returned)) {
        DWORD bufferUsed = 0;
        DWORD propertyCount = 0;
        EVT_VARIANT* buffer = NULL;
        DWORD bufferSize = 0;

        if (!EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, buffer, &bufferUsed, &propertyCount)) {
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                buffer = (EVT_VARIANT*)malloc(bufferUsed);
                bufferSize = bufferUsed;
                EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, buffer, &bufferUsed, &propertyCount);
            }
        }

        if (buffer) {
            SetConsoleRedText();
            wcout << L"[Aethers Scanner] Event Error: " << (WCHAR*)buffer << endl;
            ResetConsoleText();
            free(buffer);
        }

        EvtClose(hEvent);
    }

    EvtClose(hResults);
}


void CheckPowerShellBypasses() {
    vector<string> suspiciousPatterns = {
        "Invoke-Expression", "IEX", "DownloadString", "DownloadFile", "-nop", "-w hidden", "-enc", "Base64Decode"
    };

    ifstream powershellLogs("C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx", ios::binary);
    if (!powershellLogs.is_open()) {
        cerr << "Failed to open PowerShell logs." << endl;
        return;
    }

    const size_t bufferSize = 4096;
    char buffer[bufferSize];

    while (powershellLogs.read(buffer, bufferSize) || powershellLogs.gcount() > 0) {
        string data(buffer, powershellLogs.gcount());
        for (const auto& pattern : suspiciousPatterns) {
            if (data.find(pattern) != string::npos) {
                SetConsoleRedText();
                cout << "[Aethers Scanner] Possible PowerShell Bypass Detected: " << pattern << endl;
                ResetConsoleText();
            }
        }
    }

    powershellLogs.close();
}
void CheckFilelessExecution() {
    vector<string> filelessIndicators = {
        "Invoke-ReflectivePEInjection", "memory-only", "RunDLL", "MSHTA", "JavaScript", "WMI"
    };

    ifstream powershellLogs("C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx", ios::binary);
    if (!powershellLogs.is_open()) {
        cerr << "Failed to open PowerShell logs." << endl;
        return;
    }

    const size_t bufferSize = 4096;
    char buffer[bufferSize];

    while (powershellLogs.read(buffer, bufferSize) || powershellLogs.gcount() > 0) {
        string data(buffer, powershellLogs.gcount());
        for (const auto& indicator : filelessIndicators) {
            if (data.find(indicator) != string::npos) {
                SetConsoleRedText();
                cout << "[Aethers Scanner] Fileless Execution Indicator Detected: " << indicator << endl;
                ResetConsoleText();
            }
        }
    }

    powershellLogs.close();
}

void CheckPrefetchForDownloads() {
    string prefetchPath = "C:\\Windows\\Prefetch";
    vector<string> suspiciousApps = {
        "CURL.EXE", "BITSADMIN.EXE", "POWERSHELL.EXE", "WGET.EXE", "CERTUTIL.EXE"
    };

    for (const auto& entry : fs::directory_iterator(prefetchPath)) {
        string filename = entry.path().filename().string();
        for (const auto& app : suspiciousApps) {
            if (filename.find(app) != string::npos) {
                SetConsoleRedText();
                cout << "[Aethers Scanner] Suspicious Application in Prefetch Detected: " << filename << endl;
                ResetConsoleText();
            }
        }
    }
}

void CheckPrefetchDisabled() {
    HKEY hKey;
    DWORD value;
    DWORD valueSize = sizeof(value);
    LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", 0, KEY_READ, &hKey);

    if (result == ERROR_SUCCESS) {
        result = RegGetValue(hKey, NULL, L"EnablePrefetcher", RRF_RT_REG_DWORD, NULL, &value, &valueSize);
        if (result == ERROR_SUCCESS) {
            if (value == 0) {
                SetConsoleRedText();
                wcout << L"[Aethers Scanner] Prefetch is Disabled in Registry." << endl;
                ResetConsoleText();
            }
        }
        else {
            wcerr << L"Failed to read EnablePrefetcher value." << endl;
        }
        RegCloseKey(hKey);
    }
    else {
        wcerr << L"Failed to open Prefetch registry key." << endl;
    }
}

void SearchDiskData(const vector<string>& targets) {
    HANDLE diskHandle = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (diskHandle == INVALID_HANDLE_VALUE) {
        SetConsoleRedText();
        wcerr << L"[Aethers Scanner] Failed to open physical drive." << endl;
        ResetConsoleText();
        return;
    }

    const size_t bufferSize = 4096;
    char buffer[bufferSize];
    DWORD bytesRead;
    int foundCount = 0;

    auto startTime = chrono::steady_clock::now();

    while (ReadFile(diskHandle, buffer, bufferSize, &bytesRead, NULL) && bytesRead > 0) {
        auto currentTime = chrono::steady_clock::now();
        auto elapsedTime = chrono::duration_cast<chrono::minutes>(currentTime - startTime);
        if (elapsedTime.count() >= 2) {
            SetConsoleRedText();
            cout << "[Aethers Scanner] Skipping raw memory search due to timeout." << endl;
            ResetConsoleText();
            break;
        }

        string data(buffer, bytesRead);
        for (const auto& target : targets) {
            size_t pos = 0;
            while ((pos = data.find(target, pos)) != string::npos) {
                if (foundCount >= 5) {
                    CloseHandle(diskHandle);
                    return;
                }

                size_t end = data.find('\0', pos);
                string fullString = (end != string::npos) ? data.substr(pos, end - pos) : data.substr(pos);

                SetConsoleRedText();
                cout << "[Aethers Scanner] Found in Raw Memory, Cheating Traces : " << target << " | Full String: " << fullString << endl;
                ResetConsoleText();

                foundCount++;
                pos += target.size();
            }
        }
    }

    CloseHandle(diskHandle);
}
void CheckRAMDisks() {
    DWORD drives = GetLogicalDrives();
    if (drives == 0) {
        cerr << "Failed to get logical drives." << endl;
        return;
    }

    wchar_t driveLetter = L'A';
    while (drives) {
        if (drives & 1) {
            wchar_t rootPath[] = { driveLetter, L':', L'\', L' };

            wchar_t volumeName[MAX_PATH];
            if (GetVolumeInformationW(rootPath, volumeName, MAX_PATH, NULL, NULL, NULL, NULL, 0)) {
                wstring volumeNameStr(volumeName);
                if (volumeNameStr.find(L"RAMDisk") != wstring::npos) {
                    SetConsoleRedText();
                    wcout << L"[Aethers Scanner] RAM Disk Detected: " << rootPath << endl;
                    ResetConsoleText();
                }
            }
            }
            drives >>= 1;
            driveLetter++;
        }
    }
void CheckPageFile() {
    HKEY hKey;
    LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        DWORD valueSize = 1024;
        wchar_t value[1024];
        result = RegQueryValueEx(hKey, L"PagingFiles", NULL, NULL, (LPBYTE)value, &valueSize);
        if (result == ERROR_SUCCESS) {
            wstring pagingFile(value);
            if (pagingFile.find(L"RAMDisk") != wstring::npos) {
                SetConsoleRedText();
                wcout << L"[Aethers Scanner] RAM Disk used as Paging File Detected." << endl;
                ResetConsoleText();
            }
        }
        else {
            wcerr << L"Failed to read PagingFiles value." << endl;
        }
        RegCloseKey(hKey);
    }
    else {
        wcerr << L"Failed to open Memory Management registry key." << endl;
    }
}
#include <iptypes.h>
#include <iphlpapi.h>
#include <regex>
#include <unordered_set>
#pragma comment(lib, "Iphlpapi.lib")

void CheckPhysicalMemory() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    if (GlobalMemoryStatusEx(&statex)) {
        if (statex.ullTotalPhys < (2 * 1024ULL * 1024ULL * 1024ULL)) {
            SetConsoleRedText();
            wcout << L"[Aethers Scanner] Physical memory size is unusually low, possible RAM disk usage." << endl;
            ResetConsoleText();
        }
    }
    else {
        wcerr << L"Failed to get physical memory status." << endl;
    }
}
void CheckVirtualMachine() {
    vector<string> vmIndicators = {
        "VBOX", "VMWARE", "QEMU", "VIRTUAL", "XEN"
    };

     HKEY hKey;
    LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        DWORD valueSize = 1024;
        wchar_t value[1024];
        result = RegQueryValueEx(hKey, L"SystemBiosVersion", NULL, NULL, (LPBYTE)value, &valueSize);
        if (result == ERROR_SUCCESS) {
            wstring biosInfo(value);
            for (const auto& indicator : vmIndicators) {
                if (biosInfo.find(wstring(indicator.begin(), indicator.end())) != wstring::npos) {
                    SetConsoleRedText();
                    wcout << L"[Aethers Scanner] Virtual Machine Indicator Detected in BIOS: " << biosInfo << endl;
                    ResetConsoleText();
                }
            }
        }
        RegCloseKey(hKey);
    }

     IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBufLen = sizeof(AdapterInfo);
    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
    if (dwStatus == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
        while (pAdapterInfo) {
            string macAddr(pAdapterInfo->Address, pAdapterInfo->Address + pAdapterInfo->AddressLength);
            for (const auto& indicator : vmIndicators) {
                if (macAddr.find(indicator) != string::npos) {
                    SetConsoleRedText();
                    cout << "[Aethers Scanner] Virtual Machine Indicator Detected in MAC Address: " << macAddr << endl;
                    ResetConsoleText();
                }
            }
            pAdapterInfo = pAdapterInfo->Next;
        }
    }
}
#define SCANNER_NAME "[Aethers scanner]"
void scanLogs(const std::string& logPath) {
    std::ifstream logFile(logPath);
    if (!logFile.is_open()) {
        std::cerr << SCANNER_NAME << " Could not open log file: " << logPath << std::endl;
        return;
    }

    std::string line;
    std::regex pattern("(keyauth|keyauth\.win|skript\.gg|keyauth\.cc|shey\.tech|pedrin\.cc|projectcheats\.com|skript\.gg/support|visualsettings\.bat|tzproject\.com|api\.tzproject\.com)");
    while (std::getline(logFile, line)) {
        if (std::regex_search(line, pattern)) {
            SetConsoleTextYellow(); std::cout << SCANNER_NAME << " Detected suspicious request in log: " << logPath << std::endl;
            SetConsoleTextYellow(); std::cout << " -> " << line << std::endl;
        }
    }

    logFile.close();
}

void scanLogsForPatterns(const std::string& logPath) {
    std::ifstream file(logPath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[Aethers Scanner] Error: Could not open file " << logPath << std::endl;
        return;
    }

    std::string content;
    file.seekg(0, std::ios::end);
    content.resize(file.tellg());
    file.seekg(0, std::ios::beg);
    file.read(&content[0], content.size());
    file.close();

    std::regex pattern("(skript\\.gg|keyauth\\.cc|keyauth\\.win|shey\\.tech|pedrin\\.cc|projectcheats\\.com|skript\\.gg/support|visualsettings\\.bat|tzproject\\.com|api\\.tzproject\\.com)");
    std::smatch matches;
    if (std::regex_search(content, matches, pattern)) {
        SetConsoleTextYellow();
        std::cout << "[Aethers Scanner] Detected suspicious pattern in log file: " << logPath << std::endl;
        for (const auto& match : matches) {
            std::cout << " -> " << match << std::endl;
        }
        SetConsoleTextReset();
    }
}

void scanBrowserLogs() {
    std::vector<std::string> logPaths = {
        getenv("LOCALAPPDATA") + std::string("\\Microsoft\\Edge\\User Data\\Default\\History"),
        getenv("APPDATA") + std::string("\\Mozilla\\Firefox\\Profiles"),
        getenv("LOCALAPPDATA") + std::string("\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History"),
        getenv("LOCALAPPDATA") + std::string("\\Opera Software\\Opera Stable\\History"),
        getenv("LOCALAPPDATA") + std::string("\\Google\\Chrome\\User Data\\Default\\History")
    };

    for (const auto& logPath : logPaths) {
        if (fs::exists(logPath)) {
            auto fileSize = fs::file_size(logPath);
            if (fileSize < 1000) {
                SetConsoleTextYellow();
                std::cout << "[Aethers Scanner] Warning: Log file size is less than 1000KB, it might have been deleted: " << logPath << std::endl;
                SetConsoleTextReset();
            }
            std::cout << "[Aethers Scanner] Scanning log file: " << logPath << std::endl;
            scanLogsForPatterns(logPath);
        }
        else {
            std::cout << "[Aethers Scanner] Log file not found: " << logPath << std::endl;
        }
    }
}
std::string calculateSimpleHash(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return "";

    std::hash<std::string> hasher;
    std::ostringstream oss;
    char buffer[8192];
    while (file.read(buffer, sizeof(buffer))) {
        oss << hasher(std::string(buffer, file.gcount()));
    }
    oss << hasher(std::string(buffer, file.gcount()));
    return oss.str();
}

void scanForKnownCheatFiles(const std::vector<std::string>& knownHashes) {
    for (const auto& entry : fs::recursive_directory_iterator("C:\\")) {
        if (fs::is_regular_file(entry.path())) {
            std::string hash = calculateSimpleHash(entry.path().string());
            if (std::find(knownHashes.begin(), knownHashes.end(), hash) != knownHashes.end()) {
                SetConsoleTextYellow();
                std::cout << SCANNER_NAME << " Detected known cheat file: " << entry.path() << std::endl;
                SetConsoleTextReset();
            }
        }
    }
}

void scanDLLHijacking() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << SCANNER_NAME << " Failed to take module snapshot." << std::endl;
        return;
    }

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(snapshot, &moduleEntry)) {
        do {
            std::wstring moduleNameW = moduleEntry.szModule;
            std::string moduleName(moduleNameW.begin(), moduleNameW.end());
            if (moduleName.find(".dll") != std::string::npos) {
                SetConsoleTextYellow();
                std::cout << SCANNER_NAME << " Detected suspicious DLL: " << moduleName << std::endl;
                SetConsoleTextReset();
            }
        } while (Module32Next(snapshot, &moduleEntry));
    }
    CloseHandle(snapshot);
}


void scanProcessIntegrity() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << SCANNER_NAME << " Failed to take process snapshot." << std::endl;
        return;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &processEntry)) {
        do {
            std::wstring exeFileW = processEntry.szExeFile;
            std::string exeFile(exeFileW.begin(), exeFileW.end());
            if (exeFile.find("cheat") != std::string::npos) {
                SetConsoleTextYellow();
                std::cout << SCANNER_NAME << " Detected suspicious process: " << processEntry.szExeFile << std::endl;
                SetConsoleTextReset();
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    CloseHandle(snapshot);
}


void scanFileIntegrity() {
    std::unordered_set<std::string> protectedFiles = {
        "C:\\Windows\\System32\\ntdll.dll",
        "C:\\Windows\\System32\\kernel32.dll"
    };

    for (const auto& file : protectedFiles) {
        if (!fs::exists(file)) {
            SetConsoleTextYellow();
            std::cout << SCANNER_NAME << " Warning: Protected file missing: " << file << std::endl;
            SetConsoleTextReset();
        }
    }
}

void AntiDebugging() {
    if (IsDebuggerPresent()) {
        MessageBox(NULL, L"Debugger detected. Exiting...", L"Security Alert", MB_ICONERROR);
        ExitProcess(0);
    }

    HANDLE hProcess = GetCurrentProcess();
    BOOL isBeingDebugged = FALSE;
    CheckRemoteDebuggerPresent(hProcess, &isBeingDebugged);
    if (isBeingDebugged) {
        MessageBox(NULL, L"Remote debugger detected. Exiting...", L"Security Alert", MB_ICONERROR);
        ExitProcess(0);
    }
}

void AntiDumping() {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pDosHeader + pDosHeader->e_lfanew);

    DWORD oldProtect;
    VirtualProtect(&pNtHeaders->OptionalHeader, sizeof(pNtHeaders->OptionalHeader), PAGE_READONLY, &oldProtect);
}

void HideThreads() {
    typedef NTSTATUS(WINAPI* pNtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
    pNtSetInformationThread NtSIT = (pNtSetInformationThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtSetInformationThread");
    if (NtSIT) {
        NtSIT(GetCurrentThread(), 0x11, 0, 0);  
    }
}
#include <intrin.h>
#include <winnt.h>
bool isTestModeEnabled() {
    BOOL testMode = FALSE;
    testMode = GetSystemMetrics(SM_CLEANBOOT);
    return (testMode != 0);
}

bool isDSEPatched() {
    const char* driverPath = xorstr_("\\\\.\\NAL");   
    HANDLE hDriver = CreateFileA(driverPath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        return false;
    }
    else {
        CloseHandle(hDriver);
        return true;
    }
}
bool isDebuggerPresent() {
    return IsDebuggerPresent();
}

 

bool isVirtualMachine() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    return ((cpuInfo[2] >> 31) & 1) != 0;
}
bool isDriverDetectedByMSR() {
    const unsigned long MSR_REGISTER = 0x1C9;  
    unsigned __int64 msrValue = __readmsr(MSR_REGISTER);

    if (msrValue == 0xDEADBEEF) { 
        return true;
    }
    return false;
}
bool isDiskSpaceSuspicious() {
    ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
    if (GetDiskFreeSpaceEx(L"C:\\", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
        if (totalNumberOfBytes.QuadPart < (50ULL * 1024 * 1024 * 1024)) { 
            return true;
        }
    }
    return false;
}
bool isSandboxEnvironment() {
    const wchar_t* sandboxProcesses[] = { L"vmsrvc.exe", L"vmusrvc.exe", L"vboxservice.exe", L"vboxtray.exe" };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            for (auto& procName : sandboxProcesses) {
                if (wcscmp(pe.szExeFile, procName) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return false;
}

bool isKnownTrackingSoftwarePresent() {
    const wchar_t* trackingProcesses[] = { L"wireshark.exe", L"fiddler.exe", L"processhacker.exe", L"procmon.exe" };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            for (auto& procName : trackingProcesses) {
                if (wcscmp(pe.szExeFile, procName) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return false;
}
std::vector<std::wstring> servicesToClose = {
    L"FaceitAntiCheat",
    L"AnotherServiceName"
};

bool stopService(const std::wstring& serviceName) {
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scManager) {
         return false;
    }

    SC_HANDLE serviceHandle = OpenService(scManager, serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!serviceHandle) {
         CloseServiceHandle(scManager);
        return false;
    }

    SERVICE_STATUS status = {};
    if (ControlService(serviceHandle, SERVICE_CONTROL_STOP, &status)) {
     }
    else {
     }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scManager);
    return true;
}
int wmain(int argc, wchar_t* argv[])
{
     SetConsoleTitle(L"Aethers.cc");
    AntiDebugging();
    AntiDumping();
    HideThreads();
    if (isTestModeEnabled()) {
        return 0;
    }

 

    if (isDebuggerPresent()) {
        return 0;
    }

    

    if (isVirtualMachine()) {
        return 0;
    }
    if (isDiskSpaceSuspicious()) {
        return 0;
    }

    if (isSandboxEnvironment()) {
        return 0;
    }

    if (isKnownTrackingSoftwarePresent()) {
        return 0;
    }

    ClearScreen();
 
    std::cout << "*******************************************" << std::endl;
    std::cout << "*                                         *" << std::endl;
    std::cout << "*               AETHERS                   *" << std::endl;
    std::cout << "*                                         *" << std::endl;
    std::cout << "*******************************************" << std::endl;
    std::cout << std::endl;
    std::cout << "Make sure you read the DOCS before continuing." << std::endl;
    std::cout << "By continuing, you are also accepting the Terms and Conditions of the application." << std::endl;
    std::cout << std::endl;
    std::cout << "Press any key to continue..." << std::endl;
    _getch();
    ClearScreen();

    HANDLE hCheck = OpenDriverHandle();
    if (hCheck == NULL)
    {
        HINTERNET hInternet = InternetOpenA("Aether", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) {
            return 1;
        }

        HINTERNET hConnect = InternetOpenUrlA(hInternet, "https://aethers.cc/sexy_baby.php", "X-Aether: true\r\n", 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE, 0);
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return 1;
        }

        char buffer[4096];
        DWORD bytesRead;
        std::string encryptedResponse;

        while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {
            encryptedResponse.append(buffer, bytesRead);
        }

        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);

        if (encryptedResponse.empty()) {
            return 1;
        }

        std::string decryptedResponse = decryptResponse(encryptedResponse);
        if (decryptedResponse.empty()) {
            return 1;
        }
        std::vector<BYTE> rawData(decryptedResponse.begin(), decryptedResponse.end());
        const BYTE* bytePointer = rawData.data();
        std::cout << bytePointer;
        bool alertTriggered = false;
    
        for (const auto& serviceName : servicesToClose) {
            if (stopService(serviceName)) {
                alertTriggered = true;
            }
        }
 // Loading Driver has been removed :0

    }

    

    if (!SetDebugPrivileges())
    {
        wprintf(L"Failed to set SeDebugPrivilege. Some operations may fail.\n");
    }
    discord();
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == NULL)
    {
        wprintf(L"Failed to open driver. Exiting.\n");
        return 1;
    }

    std::wstring processName = L"lsass.exe";
    DWORD pidsa = GetProcessIdByName(processName);
    if (pidsa == 0)
    {
        wprintf(L"Process lsass.exe not found or access denied.\n");
    }

    wprintf(L"Searching in memory strings:\n");

    HANDLE hProcess = NULL;
    ACCESS_MASK desiredAccess = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

    if (AethersOpenProcess(hDevice, pidsa, desiredAccess, hProcess))
    {
        StringCleaner sc(pidsa, {
 
            "skript.gg",
            "keyauth.cc",
            "keyauth.win",
            "shey.tech",
            "pedrin.cc",
            "projectcheats.com",
            "skript.gg/support",
            "visualsettings.bat",
            "tzproject.com",
            "api.tzproject.com",
            "2024/01/20:11:56:54"
            });

        sc.findStrings(hProcess);


    }
    else
    {
        wprintf(L"Failed to open process lsass.exe.\n");
    }
    explorer();
    searchindexer();
    std::wstring target_cmdline = L"-k NetworkService -p -s Dnscache";

    std::vector<DWORD> svchost_pids = get_svchost_process_ids_by_cmdline(target_cmdline);

    if (svchost_pids.empty()) {
        std::cout << "[Aethers Scanner] THE SERVICE HAS BEEN CLOSED/ALTERCATED, CHECK USER WITH PROCESS HACKER! [Dnscache]" << std::endl;
    }
    else {
        for (DWORD pid : svchost_pids) {
             std::vector<std::string> strings_taho_clean = {
                "skript.gg",
                "skript.gg0Y0",
     "tzproject",
                "keyauth.win",
                "!!winhlp64.exe!2023 / 12 / 13:20 : 14 : 01!0!",
                "winhlp64.exe",
                "!!d3dconfig.exe!2023 / 12 / 13:20 : 14 : 01!0!",
                "d3dconfig.exe",
                "!d3dconfig",
                "!!d3dconfig",
                "d3dconfig",
                "api.tzproject.com",
                "tzproject.com",
                "2024/01/20:11:56:54"
            };


            HANDLE hCacaasd = AethersOpenProcess(hDevice, pid, desiredAccess, hCacaasd);

            StringCleaner ahrsawaw(pid, strings_taho_clean);
            ahrsawaw.findStrings(hCacaasd);

 
            CloseHandle(hCacaasd);
        }
    }
    pcasvc();
    WinHttpAutoProxySvc();
    UnistackSvcGroup(); 
    clipboard();
    std::wstring target_process_name = L"dllhost.exe";
    std::vector<DWORD> dllhost_pids = get_all_process_ids(target_process_name);

    if (dllhost_pids.empty()) {
        std::wcout << L"No instances of dllhost.exe found.\n";
        CloseHandle(hDevice);
        return 0;
    }

    for (const DWORD pid : dllhost_pids) {
 
         HANDLE hProcesadss = AethersOpenProcess(hDevice, pid, desiredAccess, hProcesadss);
        if (hProcesadss == NULL || hProcesadss == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to open process with PID " << pid << ". Error: " << GetLastError() << std::endl;
            continue;
        }
        std::vector<std::string> strings_taho_clean = { "skript.gg", "skript.gg0Y0",   "keyauth.win", "!!winhlp64.exe!2023 / 12 / 13:20 : 14 : 01!0!", "winhlp64.exe", "!!d3dconfig.exe!2023 / 12 / 13:20 : 14 : 01!0!", "d3dconfig.exe", "!d3dconfig", "!!d3dconfig", "d3dconfig", "api.tzproject.com", "tzproject.com" };

         StringCleaner cleaner(pid, strings_taho_clean);

         std::map<std::string, std::vector<size_t>> cleaned_strings = cleaner.findStrings(hProcesadss);
 
        

         CloseHandle(hProcesadss);
    }
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);


    ULONGLONG uptime = GetTickCount64();
    ULONGLONG milliseconds_in_an_hour = 3600000;

    if (uptime < milliseconds_in_an_hour) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN);
        std::cout << "Pc recently restarted, boot time: " << uptime / 1000 << " seconds ago." << std::endl;
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    HANDLE hVol = CreateFile(TEXT("\\\\.\\C:"),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hVol == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateFile failed with error: " << GetLastError() << "\n";
        return 1;
    }

    USN_JOURNAL_DATA_V0 journalData = {};
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hVol,
        FSCTL_QUERY_USN_JOURNAL,
        NULL,
        0,
        &journalData,
        sizeof(journalData),
        &bytesReturned,
        NULL)) {
        std::cerr << "FSCTL_QUERY_USN_JOURNAL failed with error: " << GetLastError() << "\n";
        CloseHandle(hVol);
        return 1;
    }

    READ_USN_JOURNAL_DATA_V0 readData = {};
    readData.StartUsn = journalData.FirstUsn;
    readData.ReasonMask = 0xFFFFFFFF; // Read all events
    readData.UsnJournalID = journalData.UsnJournalID;
    readData.BytesToWaitFor = 0;
    readData.Timeout = 0;

    CHAR buffer[4096];
    DWORD bytesRead = 0;
    if (!DeviceIoControl(hVol,
        FSCTL_READ_USN_JOURNAL,
        &readData,
        sizeof(readData),
        buffer,
        sizeof(buffer),
        &bytesRead,
        NULL)) {
        std::cerr << "FSCTL_READ_USN_JOURNAL failed with error: " << GetLastError() << "\n";
        CloseHandle(hVol);
        return 1;
    }

    PUSN_RECORD usnRecord = (PUSN_RECORD)(buffer + sizeof(USN));
     time_t currentTime = time(nullptr);

    while ((PCHAR)usnRecord < buffer + bytesRead) {
        LARGE_INTEGER timestamp;
        timestamp.QuadPart = usnRecord->TimeStamp.QuadPart;

        FILETIME fileTime;
        fileTime.dwLowDateTime = timestamp.LowPart;
        fileTime.dwHighDateTime = timestamp.HighPart;

        SYSTEMTIME systemTime;
        if (!FileTimeToSystemTime(&fileTime, &systemTime)) {
            std::cerr << "Failed to convert FILETIME to SYSTEMTIME.\n";
            usnRecord = (PUSN_RECORD)((PCHAR)usnRecord + usnRecord->RecordLength);
            continue;
        }

        struct tm timeStruct = {};
        timeStruct.tm_year = systemTime.wYear - 1900;
        timeStruct.tm_mon = systemTime.wMonth - 1;
        timeStruct.tm_mday = systemTime.wDay;
        timeStruct.tm_hour = systemTime.wHour;
        timeStruct.tm_min = systemTime.wMinute;
        timeStruct.tm_sec = systemTime.wSecond;
        time_t journalCreationTime = mktime(&timeStruct);

        if (journalCreationTime == -1) {
            std::cerr << "Failed to convert SYSTEMTIME to time_t.\n";
            usnRecord = (PUSN_RECORD)((PCHAR)usnRecord + usnRecord->RecordLength);
            continue;
        }

        double differenceInSeconds = difftime(currentTime, journalCreationTime);
        int differenceInDays = static_cast<int>(differenceInSeconds / (60 * 60 * 24));

        if (differenceInDays <= 7) {
            if (differenceInDays <= 3) {
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
            }
            else {
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            }
            std::cout << "\n\n[Journal Aethers] Journal Recently Cleaned (probably), first usn record time: " << ctime(&journalCreationTime) << " (< " << differenceInDays << " days)" << std::endl;
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        }
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

        if (systemTime.wYear >= 2024) {
            std::cout << "First USN Journal Timestamp: " << systemTime.wYear << "-"
                << std::setw(2) << std::setfill('0') << systemTime.wMonth << "-"
                << std::setw(2) << std::setfill('0') << systemTime.wDay << " "
                << std::setw(2) << std::setfill('0') << systemTime.wHour << ":"
                << std::setw(2) << std::setfill('0') << systemTime.wMinute << ":"
                << std::setw(2) << std::setfill('0') << systemTime.wSecond << "\n";
            break;
        }

        usnRecord = (PUSN_RECORD)((PCHAR)usnRecord + usnRecord->RecordLength);
    }

    CloseHandle(hVol);



    CloseDriverHandle(hDevice);
    vector<string> targets = {   "skript.gg", "tzxproject", "keyauth", "purity.exe", "J:\\svchost.exe",
        "x64a.rpf", "imdisk0", "importopti.py",
        "ZC-loadout", "loader.vmp", "settings.cock", "java64.dll", "gdx-freetype64.dll",
        "lwjgl.dll", "hsperfdata", "IMGUI", ".dll.x", "FXSEXT.exe", "abc.abc", "windbg",
        "PsExec.exe", "procdump.exe", "Osfmount", "cfg.latest", "favorites.cfg",
        "CZltWMtLL5xBgZ2M", "IMJJPUEX.EXE", "bleachbit.exe", "RWClean.exe", "J:\\svchost.exe",
        "wvpci.exe", "AMDE34B.DAT", "appmgts.exe", "appmgmts.exe", "AppCrash_appmgmts.exe" };

    CheckUSBDevices();
    CheckRemovedDevices();
    std::cout << "\n Searching Registries:\n";

    EnumerateRegistryKeys(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\USB");
    CheckRemovedRegistryKeys();
    std::cout << "\n Event Viewer:\n";

    CheckEventLogModifications(L"Application");
    CheckEventLogModifications(L"Security");
    std::cout << "\n Services:\n";
    std::vector<std::wstring> services = { L"SystemEventsBroker", L"SysMain", L"Ntfs" };

    for (const auto& service : services) {
        if (!IsServiceRunning(service)) {
            SetConsoleTextRed();
            std::wcout << L"[Aether Scanner] The Service: " << service << L" is closed." << std::endl;
            ResetConsoleText();
        }
        else if (HasServiceRestarted(service)) {
            SetConsoleTextRed();
            std::wcout << L"[Aether Scanner] The Service: " << service << L" has been restarted." << std::endl;
            ResetConsoleText();
        }
    }

    std::cout << "\n Disk:\n";
    SearchDiskData(targets);
    jrnlcheck();
    

 /*   std::cout << "\n Ram Search:\n";
    SearchRAM();*/
    std::vector<std::wstring> u_776655 = {
        L"ProcessHacker2.exe",
        L"loader_prod.exe",
        L"rawaccel.exe",
        L"launcher.exe",
        L"USBDeview.exe",
        L"loader.exe",
        L"cheat.exe",
        L"ida64.exe",
        L"ProcessHacker.exe"
    };

    sub_98765432101234567890(L"C:", u_776655);
    bool u_111111 = sub_09876543211234567890();
    bool u_222222 = sub_98765432112345678901(L"\\\\.\\C:");

    sub_9876543210987654321();
    sub_9876543210987654322();
    sub_9876543210987654323();
    sub_9876543210987654324();

    sub_9876543210987654325();
    sub_9876543210987654328();
    sub_9876543210987654329();
    sub_9876543210987654330();
    sub_9876543210987654331();
    //sub_9876543210987654332();
  //  sub_9876543210987654334();
    sub_9876543210987654335();
   

    //HANDLE diskHandle = CreateFile(
    //    L"\\.\PhysicalDrive0",
    //    GENERIC_READ,
    //    FILE_SHARE_READ | FILE_SHARE_WRITE,
    //    NULL,
    //    OPEN_EXISTING,
    //    0,
    //    NULL);

    //if (diskHandle == INVALID_HANDLE_VALUE)
    //{
    //    std::cerr << "Failed to open disk handle. Error: " << GetLastError() << std::endl;
    //    return 1;
    //}

    //std::vector<std::string> sectorData;
    //DWORD startSector = 0; // Starting at sector 0
    //DWORD sectorCount = 100; // Reading 100 sectors

    //if (!readDiskSectors(diskHandle, sectorData, startSector, sectorCount))
    //{
    //    CloseHandle(diskHandle);
    //    return 1;
    //}

    //// List of strings to search for
    //std::vector<std::string> searchStrings = {
    //    "skript.gg",   "purity.exe", "J:\\svchost.exe",
    //    "x64a.rpf", "imdisk0", "delete", "imgui.ini", "importopti.py",
    //    "ZC-loadout", "loader.vmp", "settings.cock", "file:///A", "file:///B", "file:///F", "file:///G",
    //    "file:///H", "file:///I", "file:///J", "file:///K", "file:///L", "file:///M",
    //    "loader.cfg", "menyoLog.txt", "Boot.sdi", "file:///N", "file:///Q", "file:///P",
    //    "file:///O", "file:///R", "file:///S", "file:///T", "file:///U", "file:///V",
    //    "file:///W", "file:///X", "file:///Y", "file:///Z", "java64.dll", "gdx-freetype64.dll",
    //    "lwjgl.dll", "hsperfdata", "IMGUI", ".dll.x", "FXSEXT.exe", "abc.abc", "windbg",
    //    "PsExec.exe", "procdump.exe", "Osfmount", "cfg.latest", "favorites.cfg",
    //    "CZltWMtLL5xBgZ2M", "IMJJPUEX.EXE", "bleachbit.exe", "RWClean.exe", "J:\\svchost.exe",
    //    "wvpci.exe", "AMDE34B.DAT", "appmgts.exe", "appmgmts.exe", "AppCrash_appmgmts.exe"
    //};

    //// Search for strings in the disk sectors
    //if (searchForStrings(sectorData, searchStrings))
    //{
    //    CloseHandle(diskHandle);
    //    return 0;
    //}

    //std::cout << "No matches found." << std::endl;
    //CloseHandle(diskHandle);
    ResetConsoleText();

    CheckLoadedVHDs();
    CheckMountedVHDs();
    CheckUnusedSpace();
     CheckOtherDrivesForDLLs();
     std::cout << "\n Powershell:\n";
     CheckEventViewerErrors();
     CheckPowerShellBypasses();
     CheckFilelessExecution();

     std::cout << "\n Prefetch:\n";
     CheckPrefetchForDownloads();
     CheckPrefetchDisabled();

     std::cout << "\n RAM:\n";
     CheckRAMDisks();
     CheckPageFile();
     CheckPhysicalMemory();
     std::cout << "\n VM Checks [QEMU SPOOFED ALSO]:\n";
     CheckVirtualMachine();

     std::cout << "\n Networking [We don't save anything here]:\n";
     scanBrowserLogs();
     ResetConsoleText();


    std::cout << "Done!";
    _getch();
    ResetConsoleText();

     std::cin.ignore();
}


