#include "stdafx.h"
#include "utility.h"
#include "pmc.h"

UCHAR g_OrgMaxPmcCounter = 0;
ULONG_PTR g_pEtwpMaxPmcCount = 0;

NTSTATUS InitializePerformarnceCounter()
{
	NTSTATUS status = STATUS_SUCCESS;

	PVOID pNtBase = GetNtosKernelBaseAddress();
	if (pNtBase == NULL)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Failed to get ntoskrnl base address.\n");
		return STATUS_NOT_FOUND;
	}

	//
	// Get neccesary ntoskrnl global variables
	ULONG_PTR pEtwpDebuggerData = (ULONG_PTR)pNtBase + ETWP_DEBUGGER_DATA_OFFSET;
	g_pEtwpMaxPmcCount = (ULONG_PTR)pNtBase + ETWP_MAX_PMC_COUNTER_OFFSET;
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Found nt!EtwpDebuggerData=0x%p, nt!EtwpMaxPmcCount=0x%p\n", (PVOID)pEtwpDebuggerData, (PVOID)g_pEtwpMaxPmcCount);
	
	//
	// Find _WMI_LOGGER_CONTEXT address of Circular Kernel Context Logger
	// EtwpDebuggerData + 0x10 = WMI_LOGGER_CONTEXT table
	PVOID pDebuggerDataSilo = NULL;
	memcpy_s(&pDebuggerDataSilo, sizeof(PVOID), (PVOID)(pEtwpDebuggerData + 0x10), sizeof(PVOID));
	if (!MmIsAddressValid(pDebuggerDataSilo))
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Failed to get pDebuggerDataSilo.\n");
		return STATUS_INVALID_ADDRESS;
	}

	//
	// CKCL Context locates in second index of pDebuggerDataSilo
	PVOID pCKCLContext = NULL;
	memcpy_s(&pCKCLContext, sizeof(PVOID), (PVOID)((ULONG_PTR)pDebuggerDataSilo + 0x10), sizeof(PVOID));
	if (!MmIsAddressValid(pCKCLContext))
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Failed to get pCKCLContext.\n");
		return STATUS_INVALID_ADDRESS;
	}

	//
	// Check if LoggerName is Circular Kernel Context Logger
	UNICODE_STRING strCKCLContext = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");
	if (RtlCompareUnicodeString(&strCKCLContext, (PUNICODE_STRING)((ULONG_PTR)pCKCLContext + WMI_LOGGER_CONTEXT_NAME_OFFSET), TRUE) != 0)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Failed to get strCKCLContext.\n");
		return STATUS_WMI_INSTANCE_NOT_FOUND;
	}

	//
	// Get LoggerId from CKCL
	ULONG ulLoggerId = 2;
	memcpy_s(&ulLoggerId, sizeof(ULONG), (PVOID)((ULONG_PTR)pCKCLContext + WMI_LOGGER_CONTEXT_LOGGERID_OFFSET), sizeof(ULONG));
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Found Circular Kernel Context Logger: Context=0x%p, LoggerID=%ul\n", pCKCLContext, ulLoggerId);

	//
	// Check EtwpMaxPmcCounter is 1 and expand it to use EventTraceProfileCounterListInformation
	UCHAR ucCount = *(UCHAR*)(g_pEtwpMaxPmcCount);
	if (ucCount <= 1)
	{
		g_OrgMaxPmcCounter = ucCount;
		*(UCHAR*)(g_pEtwpMaxPmcCount) = 2;
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Expanded EtwpMaxPmcCounter to use additional EventTraceProfileCounterListInformation.\n");
	}

	//
	// Now register performance counter events for CKCL ETW provider
	PEVENT_TRACE_PROFILE_COUNTER_INFORMATION counterInformation = (PEVENT_TRACE_PROFILE_COUNTER_INFORMATION)ExAllocatePool(PagedPool, PAGE_SIZE);
	if (counterInformation == NULL)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Failed to allocate memory at EventTraceProfileCounterListInformation. (NTSTATUS=0x%X)\n", status);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	counterInformation->EventTraceInformationClass = EventTraceProfileCounterListInformation;
	counterInformation->TraceHandle = ulLoggerId;
	counterInformation->ProfileSource[0] = 1;

	status = ZwSetSystemInformation(SystemPerformanceTraceInformation, counterInformation, sizeof(EVENT_TRACE_PROFILE_COUNTER_INFORMATION));
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Failed EventTraceProfileCounterListInformation. (NTSTATUS=0x%X)\n", status);
		return status;
	}
	else
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Registered EventTraceProfileCounterListInformation.\n");
	}

	PEVENT_TRACE_SYSTEM_EVENT_INFORMATION traceInformation = (PEVENT_TRACE_SYSTEM_EVENT_INFORMATION)ExAllocatePool(PagedPool, PAGE_SIZE);
	if (traceInformation == NULL)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Failed to allocate memory at EventTraceProfileEventListInformation.\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	traceInformation->EventTraceInformationClass = EventTraceProfileEventListInformation;
	traceInformation->TraceHandle = ulLoggerId;
	traceInformation->HookId[0] = 0xF33;	// Syscall enter event id is 0xF33

	status = ZwSetSystemInformation(SystemPerformanceTraceInformation, traceInformation, sizeof(EVENT_TRACE_SYSTEM_EVENT_INFORMATION));
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[-] Failed EventTraceProfileEventListInformation. (NTSTATUS=0x%X)\n", status);
		return status;
	}
	else
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Registered EventTraceProfileEventListInformation. (NTSTATUS=0x%X)\n", status);
	}

	ExFreePool(traceInformation);
	ExFreePool(counterInformation);

	return status;
}

VOID RestoreEtwpMaxPmcCounter()
{
	if (g_OrgMaxPmcCounter != 0)
	{
		*(UCHAR*)(g_pEtwpMaxPmcCount) = g_OrgMaxPmcCounter;
	}
}