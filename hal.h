#pragma once

typedef void(NTAPI* _HalpCollectPmcCounters)(PVOID* pPmcCounter, unsigned long long* ullTraceBufferEnd);

NTSTATUS HookHalpCollectPmcCounters(
	_In_ PVOID pNtoskrnlBaseAddress
);

VOID UnhookHalpCollectPmcCounters();