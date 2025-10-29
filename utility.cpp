#include "stdafx.h"
#include "utility.h"

PVOID GetNtosKernelBaseAddress()
{
	UNICODE_STRING strPsLoadedModuleList = RTL_CONSTANT_STRING(L"PsLoadedModuleList");
	UNICODE_STRING strNtoskrnl = RTL_CONSTANT_STRING(L"ntoskrnl.exe");
	PVOID pPsLoadedModuleList = MmGetSystemRoutineAddress(&strPsLoadedModuleList);
	if (pPsLoadedModuleList == NULL)
		return NULL;

	PLDR_DATA_TABLE_ENTRY pCurrentEntry = (PLDR_DATA_TABLE_ENTRY)((PLDR_DATA_TABLE_ENTRY)pPsLoadedModuleList)->InLoadOrderLinks.Flink;
	while (pCurrentEntry != pPsLoadedModuleList)
	{
		if (RtlCompareUnicodeString(&pCurrentEntry->BaseDllName, &strNtoskrnl, TRUE) == 0)
		{
			return pCurrentEntry->DllBase;
		}

		pCurrentEntry = (PLDR_DATA_TABLE_ENTRY)pCurrentEntry->InLoadOrderLinks.Flink;
	}

	return NULL;
}

LPWSTR GetNearestDriverNameFromOffset(
	_In_ PVOID pOffset
)
{
	UNICODE_STRING strPsLoadedModuleList = RTL_CONSTANT_STRING(L"PsLoadedModuleList");
	PVOID pPsLoadedModuleList = MmGetSystemRoutineAddress(&strPsLoadedModuleList);
	if (pPsLoadedModuleList == NULL)
		return NULL;

	PLDR_DATA_TABLE_ENTRY pFoundEntry = NULL;
	PLDR_DATA_TABLE_ENTRY pCurrentEntry = (PLDR_DATA_TABLE_ENTRY)((PLDR_DATA_TABLE_ENTRY)pPsLoadedModuleList)->InLoadOrderLinks.Flink;
	while (pCurrentEntry != pPsLoadedModuleList)
	{
		// Check offset is larger than DllBase and nearest than any others.
		if (((ULONG_PTR)pCurrentEntry->DllBase <= (ULONG_PTR)pOffset) && ((ULONG_PTR)pOffset <= (ULONG_PTR)pCurrentEntry->DllBase + pCurrentEntry->SizeOfImage))
		{
			pFoundEntry = pCurrentEntry;
		}

		pCurrentEntry = (PLDR_DATA_TABLE_ENTRY)pCurrentEntry->InLoadOrderLinks.Flink;
	}

	if (pFoundEntry != NULL)
	{
		return pFoundEntry->BaseDllName.Buffer;
	}

	return NULL;
}