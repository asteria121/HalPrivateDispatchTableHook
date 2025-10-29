#pragma once

#pragma warning(disable : 4201)
#pragma warning(disable : 4996)

#include <ntdef.h>
#include <ntstatus.h>
#include <ntifs.h>
#include <intrin.h>

// This is just POC. You must use proper offsets or parse method. (memory signature pattern scan, ntkrnlmp.pdb, hardcode, etc...)
// Belows are hardcoded offsets from Windows 11 23H2 Build 22631.6060 and compatible with Win 11 23H2
#define ETWP_DEBUGGER_DATA_OFFSET			0xC0B4A8
#define ETWP_MAX_PMC_COUNTER_OFFSET			0xD5303C
#define KI_SYSTEM_SERVICE_REPEAT_OFFSET		0x433484
#define NT_TERMINATE_PROCESS_OFFSET			0x6837e0

/*
0: kd> dt HAL_PRIVATE_DISPATCH
nt!HAL_PRIVATE_DISPATCH
	.....
	+0x240 HalAllocatePmcCounterSet : Ptr64     long
	+0x248 HalCollectPmcCounters : Ptr64     void   <- HalpCollectPmcCounters
	+0x250 HalFreePmcCounterSet : Ptr64     void
*/
#define HALP_COLLECT_PMC_COUNTERS_OFFSET	0x248
#define WMI_LOGGER_CONTEXT_LOGGERID_OFFSET	0x00
#define WMI_LOGGER_CONTEXT_NAME_OFFSET		0x88