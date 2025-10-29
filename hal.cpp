#include "stdafx.h"
#include "hal.h"
#include "hook.h"
#include "utility.h"

_HalpCollectPmcCounters OrgHalpCollectPmcCounters = NULL;
PVOID pHalPrivateDispatchTable = NULL;
PVOID pKiSystemServiceRepeat = NULL;

VOID Hooked_HalpCollectPmcCounters(
	PVOID* pPmcCounter,
	unsigned long long* ullTraceBufferEnd
)
{
	//
	// Call original PmcCounter
	OrgHalpCollectPmcCounters(pPmcCounter, ullTraceBufferEnd);
	if (!pPmcCounter || !ullTraceBufferEnd)
		return;

	//
	// Exclude kernel mode execution
	if (ExGetPreviousMode() == KernelMode)
		return;

	if (pKiSystemServiceRepeat == NULL)
		return;

	//
	// Stack walk and check syscall routine exists
	PVOID* pKpcrStackBase = (PVOID*)__readgsqword(0x1A8); // KPCR->RSP Base (Maximum stack base)
	PVOID* pCurrentStackFrame = (PVOID*)_AddressOfReturnAddress(); // Stack Frame
	const ULONG magic1 = 0x501802;	// Stack frame magic value
	const USHORT magic2 = 0xf33;		// Stack frame magic value, also used in performance counter setup which means syscall enter event id 

	for (; pCurrentStackFrame < pKpcrStackBase; pCurrentStackFrame++)
	{
		//
		// Check magic number is correctly exists in stack frame
		PUSHORT usStack = (PUSHORT)pCurrentStackFrame;
		if (*usStack != magic2) continue;

		pCurrentStackFrame++;

		PULONG ulStack = (PULONG)pCurrentStackFrame;
		if (*ulStack != magic1) continue;

		for (; pCurrentStackFrame < pKpcrStackBase; pCurrentStackFrame++)
		{
			//
			// Check current stack frame is at pKiSystemServiceRepeat
			if ((ULONG_PTR)*pCurrentStackFrame >= (ULONG_PTR)PAGE_ALIGN(pKiSystemServiceRepeat)
				&& (ULONG_PTR)*pCurrentStackFrame <= (ULONG_PTR)PAGE_ALIGN((ULONG_PTR)pKiSystemServiceRepeat + PAGE_SIZE * 2))
			{
				//
				// Hook userland syscall
				CheckSyscall(pCurrentStackFrame);

				break;
			}
		}

		break;
	}
}

NTSTATUS HookHalpCollectPmcCounters(
	_In_ PVOID pNtoskrnlBaseAddress
)
{
	//
	// Get HalPrivateDispatchTable offset
	UNICODE_STRING strHalPrivateDispatchTable = RTL_CONSTANT_STRING(L"HalPrivateDispatchTable");
	pHalPrivateDispatchTable = MmGetSystemRoutineAddress(&strHalPrivateDispatchTable);
	if (pHalPrivateDispatchTable == NULL)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Failed to find nt!HalPrivateDispatchTable from exports.\n");
		return STATUS_NOT_FOUND;
	}

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Found nt!HalPrivateDispatchTable: 0x%p\n", pHalPrivateDispatchTable);

	//
	// Check HalpCollectPmcCounters offset
	memcpy_s(&OrgHalpCollectPmcCounters, sizeof(PVOID), (PVOID)((ULONG_PTR)pHalPrivateDispatchTable + HALP_COLLECT_PMC_COUNTERS_OFFSET), sizeof(PVOID));
	if (!MmIsAddressValid(OrgHalpCollectPmcCounters))
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Failed to get nt!HalPrivateDispatchTable->HalpCollectPmcCounters offset.\n");
		return STATUS_INVALID_ADDRESS;
	}

	//
	// Check if HalpCollectPmcCounters has already hooked by another driver
	LPWSTR wsDriverName = GetNearestDriverNameFromOffset(OrgHalpCollectPmcCounters);
	if (wsDriverName == NULL)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Unknown offset found at nt!HalPrivateDispatchTable->HalpCollectPmcCounters(): 0x%p\n", OrgHalpCollectPmcCounters);
		return STATUS_NOT_FOUND;
	}
	else if (wcscmp(L"ntoskrnl.exe", wsDriverName) != 0)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] HalPrivateDispatchTable->HalpCollectPmcCounters has already hooked by another driver: %ws\n", wsDriverName);
		return STATUS_RESOURCE_IN_USE;
	}

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Found nt!HalPrivateDispatchTable->HalpCollectPmcCounters: 0x%p)\n", OrgHalpCollectPmcCounters);

	//
	// Get KiSystemServiceRepeat offset to determine stack frame position
	pKiSystemServiceRepeat = (PVOID)((ULONG_PTR)pNtoskrnlBaseAddress + KI_SYSTEM_SERVICE_REPEAT_OFFSET);
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Found nt!KiSystemServiceRepeat(): 0x%p\n", pKiSystemServiceRepeat);

	//
	// All primitives are done, Hook HalpCollectPmcConuter by changing pointer
	PVOID pHookAddress = (PVOID)Hooked_HalpCollectPmcCounters;
	memcpy_s((PVOID)((ULONG_PTR)pHalPrivateDispatchTable + HALP_COLLECT_PMC_COUNTERS_OFFSET), sizeof(PVOID), &pHookAddress, sizeof(PVOID));

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Setting up hooking at nt!HalPrivateDispatchTable->HalpCollectPmcCounters is now complete.\n");

	return STATUS_SUCCESS;
}

VOID UnhookHalpCollectPmcCounters()
{
	memcpy_s((PVOID)((ULONG_PTR)pHalPrivateDispatchTable + HALP_COLLECT_PMC_COUNTERS_OFFSET), sizeof(PVOID), &OrgHalpCollectPmcCounters, sizeof(PVOID));
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Restoring function pointer at nt!HalPrivateDispatchTable->HalpCollectPmcCounters.\n");
}