/*
 * Author: Arthur (RTHXR)
 * 27/02/2024
 *
 * STATUS: IN PROGRESS
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
