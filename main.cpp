#include "stdafx.h"
#include "etw.h"
#include "pmc.h"
#include "utility.h"
#include "hal.h"
#include "hook.h"

VOID OnUnload(
	IN	PDRIVER_OBJECT pDriverObject
)
{
	UNREFERENCED_PARAMETER(pDriverObject);

	//
	// Release ETW with ZwTraceControl(EtwStop, ....);
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Stopping ETW service.\n");
	StopEtw();

	//
	// Restore EtwpMaxPmcCounter if modified
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Restoring nt!EtwpMaxPmcCounter.\n");
	RestoreEtwpMaxPmcCounter();

	//
	// Restore HAL_PRIVATE_DISPATCH_TABLE->HalpCollectPmcCounters
	UnhookHalpCollectPmcCounters();

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Driver unloaded. Good Bye.\n");
}

extern "C" NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING pRegistryPath
)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);

	PVOID pNtoskrnlBaseAddress = GetNtosKernelBaseAddress();
	if (pNtoskrnlBaseAddress == NULL)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Failed to get ntoskrnl base address.\n");
		return STATUS_NOT_FOUND;
	}
	
	//
	// Initialize syscall logging CKCL ETW provider
	NTSTATUS status = InitializeEtw();
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Failed to initialize ETW. (NTSTATUS=0x%X)\n", status);
		return status;
	}

	//
	// Setup performance counter for CKCL ETW provider to call HalpCollectPmcCounters
	status = InitializePerformarnceCounter();
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Failed to initialize performance counter. (NTSTATUS=0x%X)\n", status);
		StopEtw();
		return status;
	}

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] ETW service initialized.\n");

	//
	// Get address for nt!NtTerminateProcess
	// Custom hooked syscall list management method can be added
	InitializeSyscallHook(pNtoskrnlBaseAddress);

	//
	// Setup hook at HalpCollectPmcCounters
	status = HookHalpCollectPmcCounters(pNtoskrnlBaseAddress);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Failed to setup hooks at nt!HalPrivateDispatchTable->HalpCollectPmcCounters. (NTSTATUS=0x%X)\n", status);
		StopEtw();
		return status;
	}

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Ring3 syscall should be hooked now.\n");

	pDriverObject->DriverUnload = OnUnload;

	return STATUS_SUCCESS;
}