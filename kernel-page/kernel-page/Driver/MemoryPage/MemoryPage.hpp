#pragma once

#include <Windows.h>
#include <iostream>
#include <winternl.h>

#define PAGE_SHIFT      12
#ifdef __ASSEMBLY__
#define PAGE_SIZE       (1 << PAGE_SHIFT)
#else
#define PAGE_SIZE       (1UL << PAGE_SHIFT)
#endif
#define PAGE_MASK       (~(PAGE_SIZE-1))

#define IS_LARGE_PAGE(x)    ( (BOOLEAN)((x >> 7) & 1) )
#define IS_PAGE_PRESENT(x)  ( (BOOLEAN)(x & 1) )

#define PAGE_1GB_SHIFT      30
#define PAGE_1GB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_1GB_SHIFT)) )

#define PAGE_2MB_SHIFT      21
#define PAGE_2MB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_2MB_SHIFT)) )

#define PAGE_4KB_SHIFT      12
#define PAGE_4KB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_4KB_SHIFT)) )

typedef struct _MMPTE_HARDWARE
{
	ULONG64 Valid : 1;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	ULONG64 Dirty1 : 1;
#else
#ifdef CONFIG_SMP
	ULONG64 Writable : 1;
#else
	ULONG64 Write : 1;
#endif
#endif
	ULONG64 Owner : 1;
	ULONG64 WriteThrough : 1;
	ULONG64 CacheDisable : 1;
	ULONG64 Accessed : 1;
	ULONG64 Dirty : 1;
	ULONG64 LargePage : 1;
	ULONG64 Global : 1;
	ULONG64 CopyOnWrite : 1;
	ULONG64 Prototype : 1;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	ULONG64 Write : 1;
	ULONG64 PageFrameNumber : 36;
	ULONG64 reserved1 : 4;
#else
#ifdef CONFIG_SMP
	ULONG64 Write : 1;
#else
	ULONG64 reserved0 : 1;
#endif
	ULONG64 PageFrameNumber : 28;
	ULONG64 reserved1 : 12;
#endif
	ULONG64 SoftwareWsIndex : 11;
	ULONG64 NoExecute : 1;
} MMPTE_HARDWARE, * PMMPTE_HARDWARE;

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Object;
	ULONG UniqueProcessId;
	ULONG HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG NumberOfHandles;
	ULONG Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
};

struct DriverOffsetPacket {
	std::uint64_t ActiveProcessLinks;
	std::uint64_t ImageFileName;
	std::uint64_t VirtualSize;
	std::uint64_t SectionBase;
	std::uint64_t Peb;
};

typedef void* (*memmove_t)(void* Dst, void* Src, std::size_t Size);

class MemoryPage {
public:
	MemoryPage(const std::uint64_t VirtualAddress, const std::uint64_t Pte);

	bool Load(DriverOffsetPacket Packet);

	bool WriteVirtualMemory(const std::uint64_t DirectoryTable, const std::uint64_t Address, void* Buffer, const std::size_t Size);
	bool ReadVirtualMemory(const std::uint64_t DirectoryTable, const std::uint64_t Address, void* Buffer, const std::size_t Size);
	bool WritePhysicalMemory(const std::uint64_t PhysicalAddress, void* Buffer, std::size_t Size);
	bool ReadPhysicalMemory(const std::uint64_t PhysicalAddress, void* Buffer, std::size_t Size);
	std::uint64_t GetPhysicalAddress(std::uint64_t DirectoryTable, std::uint64_t VirtualAdddress);
	std::uint64_t GetSystemCr3();
private:
	std::uint64_t SetPageFrameNumber(const std::uint64_t PageFrameNumber);
	void InvalidateTlbForPage();

	std::uint64_t GetProcess(const char* Name);
	std::uint64_t GetSystemProcess();

	DriverOffsetPacket OffsetPacket;
	MMPTE_HARDWARE Struct;

	std::uint64_t Buffer;
	std::uint64_t Pte;
	memmove_t memmove;
};