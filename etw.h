#pragma once

#include "stdafx.h"

#define EtwStart	1
#define EtwStop		2
#define EtwUpdate	4

#define WNODE_FLAG_TRACED_GUID			0x00020000  // denotes a trace
#define EVENT_TRACE_BUFFERING_MODE      0x00000400  // Buffering mode only
#define EVENT_TRACE_FLAG_SYSTEMCALL     0x00000080  // system calls

typedef struct _WNODE_HEADER {
	ULONG BufferSize;
	ULONG ProviderId;
	union {
		ULONG64 HistoricalContext;
		struct {
			ULONG Version;
			ULONG Linkage;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;
	union {
		ULONG         CountLost;
		HANDLE        KernelHandle;
		LARGE_INTEGER TimeStamp;
	} DUMMYUNIONNAME2;
	GUID  Guid;
	ULONG ClientContext;
	ULONG Flags;
} WNODE_HEADER, * PWNODE_HEADER;

typedef struct _EVENT_TRACE_PROPERTIES {
	WNODE_HEADER Wnode;
	//
	// data provided by caller
	ULONG BufferSize;                   // buffer size for logging (kbytes)
	ULONG MinimumBuffers;               // minimum to preallocate
	ULONG MaximumBuffers;               // maximum buffers allowed
	ULONG MaximumFileSize;              // maximum logfile size (in MBytes)
	ULONG LogFileMode;                  // sequential, circular
	ULONG FlushTimer;                   // buffer flush timer, in seconds
	ULONG EnableFlags;                  // trace enable flags
	union {
		LONG  AgeLimit;                 // unused
		LONG  FlushThreshold;           // Number of buffers to fill before flushing
	} DUMMYUNIONNAME;

	// data returned to caller
	ULONG NumberOfBuffers;              // no of buffers in use
	ULONG FreeBuffers;                  // no of buffers free
	ULONG EventsLost;                   // event records lost
	ULONG BuffersWritten;               // no of buffers written to file
	ULONG LogBuffersLost;               // no of logfile write failures
	ULONG RealTimeBuffersLost;          // no of rt delivery failures
	HANDLE LoggerThreadId;              // thread id of Logger
	ULONG LogFileNameOffset;            // Offset to LogFileName
	ULONG LoggerNameOffset;             // Offset to LoggerName
} EVENT_TRACE_PROPERTIES, *PEVENT_TRACE_PROPERTIES;

typedef struct _CKCL_TRACE_PROPERIES : _EVENT_TRACE_PROPERTIES
{
	ULONG64			Unknown[3];
	UNICODE_STRING	ProviderName;
} CKCL_TRACE_PROPERTIES, *PCKCL_TRACE_PROPERTIES;

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwTraceControl(
	_In_ ULONG FunctionCode,
	_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
	_In_ ULONG InBufferLen,
	_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
);

NTSTATUS InitializeEtw();

NTSTATUS StopEtw();