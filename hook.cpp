#include "stdafx.h"
#include "hook.h"

typedef NTSTATUS(NTAPI* _NtTerminateProcess)(_In_opt_ HANDLE ProcessHandle, _In_ NTSTATUS ExitStatus);
_NtTerminateProcess OrgNtTerminateProcess = NULL;

VOID InitializeSyscallHook(
	_In_ PVOID pNtoskrnlBaseAddress
)
{
	OrgNtTerminateProcess = (_NtTerminateProcess)((ULONG_PTR)pNtoskrnlBaseAddress + NT_TERMINATE_PROCESS_OFFSET);
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] nt!NtTerminateProcess(): 0x%p\n", OrgNtTerminateProcess);
}

NTSTATUS Hooked_NtTerminateProcess(
	_In_opt_ HANDLE   ProcessHandle,
	_In_	 NTSTATUS ExitStatus
)
{
	//
	// Ignore HANDLE 0 and -1
	// ObReferenceObjectByHandle should be called in PASSIVE_LEVEL
	if (ProcessHandle == (HANDLE)0 || ProcessHandle == (HANDLE)-1 || KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return OrgNtTerminateProcess(ProcessHandle, ExitStatus);
	}

	//
	// Get PEPROCESS from handle
	PEPROCESS pEprocess = NULL;
	NTSTATUS status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, UserMode, (PVOID*)&pEprocess, NULL);
	if (!NT_SUCCESS(status) || pEprocess == NULL)
	{
		// If fails, call original function
		return OrgNtTerminateProcess(ProcessHandle, ExitStatus);
	}

	//
	// Prevent notepad.exe terminate by NtTerminateProcess
	HANDLE processId = PsGetProcessId(pEprocess);
	PUNICODE_STRING pstrImageName;
	status = SeLocateProcessImageName(pEprocess, &pstrImageName);
	ObDereferenceObject(pEprocess);

	if (NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[*] NtTerminateProcess(): PID=%d, %wZ\n", HandleToUlong(processId), pstrImageName);

		UNICODE_STRING strNotepad = RTL_CONSTANT_STRING(L"\\notepad.exe");
		if (RtlSuffixUnicodeString(&strNotepad, pstrImageName, TRUE) == TRUE)
		{
			return STATUS_ACCESS_DENIED;
		}
	}

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[*] NtTerminateProcess(): ProcessHandle = %p, ExitStatus = 0x%X\n", ProcessHandle, ExitStatus);
	return OrgNtTerminateProcess(ProcessHandle, ExitStatus);
}

VOID CheckSyscall(
	_In_ PVOID* pCurrentStackFrame
)
{
	//
	// Check for syscall is NtTerminateProcess
	// Syscall address is located at stackframe[9]
	PVOID pCurrentSyscall = pCurrentStackFrame[9];
	if (pCurrentSyscall == (PVOID)OrgNtTerminateProcess)
	{
		pCurrentStackFrame[9] = Hooked_NtTerminateProcess;
	}
}