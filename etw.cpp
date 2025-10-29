#include "stdafx.h"
#include "etw.h"

// Same with original CKCL ETW provider information
const GUID ckcl_etw_guid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

NTSTATUS InitializeEtw()
{
	PCKCL_TRACE_PROPERTIES pEventProperty = (PCKCL_TRACE_PROPERTIES)ExAllocatePool(NonPagedPool, PAGE_SIZE);
	if (pEventProperty == NULL)
	{
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	memset(pEventProperty, 0, PAGE_SIZE);

	// Same with original CKCL ETW provider information
	pEventProperty->Wnode.BufferSize = PAGE_SIZE;
	pEventProperty->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pEventProperty->ProviderName = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");
	pEventProperty->Wnode.Guid = ckcl_etw_guid;
	pEventProperty->Wnode.ClientContext = 1;
	pEventProperty->BufferSize = sizeof(ULONG);
	pEventProperty->MinimumBuffers = 2;
	pEventProperty->MaximumBuffers = 2;
	pEventProperty->LogFileMode = EVENT_TRACE_BUFFERING_MODE;

	NTSTATUS status = STATUS_SUCCESS;
	ULONG ulReturnLen = 0;
	
	status = ZwTraceControl(EtwStart, pEventProperty, PAGE_SIZE, pEventProperty, PAGE_SIZE, &ulReturnLen);
	if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION)
	{
		ExFreePool(pEventProperty);
		return status;
	}

	pEventProperty->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
	status = ZwTraceControl(EtwUpdate, pEventProperty, PAGE_SIZE, pEventProperty, PAGE_SIZE, &ulReturnLen);
	if (!NT_SUCCESS(status))
	{
		ZwTraceControl(EtwStop, pEventProperty, PAGE_SIZE, pEventProperty, PAGE_SIZE, &ulReturnLen);
		ExFreePool(pEventProperty);
		return status;
	}

	ExFreePool(pEventProperty);

	return status;
}

NTSTATUS StopEtw()
{
	PCKCL_TRACE_PROPERTIES pEventProperty = (PCKCL_TRACE_PROPERTIES)ExAllocatePool(NonPagedPool, PAGE_SIZE);
	if (pEventProperty == NULL)
	{
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	memset(pEventProperty, 0, PAGE_SIZE);

	// Same with original CKCL ETW provider information
	pEventProperty->Wnode.BufferSize = PAGE_SIZE;
	pEventProperty->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pEventProperty->ProviderName = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");
	pEventProperty->Wnode.Guid = ckcl_etw_guid;
	pEventProperty->Wnode.ClientContext = 1;
	pEventProperty->BufferSize = sizeof(ULONG);
	pEventProperty->MinimumBuffers = 2;
	pEventProperty->MaximumBuffers = 2;
	pEventProperty->LogFileMode = EVENT_TRACE_BUFFERING_MODE;

	NTSTATUS status = STATUS_SUCCESS;
	ULONG ulReturnLen = 0;

	status = ZwTraceControl(EtwStop, pEventProperty, PAGE_SIZE, pEventProperty, PAGE_SIZE, &ulReturnLen);

	ExFreePool(pEventProperty);

	return status;
}