#pragma once

#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

VOID InitializeSyscallHook(
	_In_ PVOID pNtoskrnlBaseAddress
);

VOID CheckSyscall(
	_In_ PVOID* pCurrentStackFrame
);