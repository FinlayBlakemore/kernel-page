#include "MemoryPage.hpp"

static NTSTATUS(__stdcall* NtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval) = (NTSTATUS(__stdcall*)(BOOL, PLARGE_INTEGER)) GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDelayExecution");
static NTSTATUS(__stdcall* ZwSetTimerResolution)(IN ULONG RequestedResolution, IN BOOLEAN Set, OUT PULONG ActualResolution) = (NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG)) GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwSetTimerResolution");

static void high_resolution_sleep(float milliseconds) { // cancer
	static bool once = true;
	if (once) {
		ULONG actualResolution;
		ZwSetTimerResolution(1, true, &actualResolution);
		once = false;
	}

	LARGE_INTEGER interval;
	interval.QuadPart = -1 * (int)(milliseconds * 10000.0f);
	NtDelayExecution(false, &interval);
}

MemoryPage::MemoryPage(const std::uint64_t VirtualAddress, const std::uint64_t Pte)
{
	this->memmove = (memmove_t)(GetProcAddress(GetModuleHandleA("win32u.dll"), "NtGdiGetStats"));
	this->Buffer = VirtualAddress;
	this->Pte = Pte;
}

bool MemoryPage::Load(DriverOffsetPacket Packet)
{
	this->OffsetPacket = Packet;

	if (!this->GetSystemProcess()) {
		return false;
	}

	if (!this->GetSystemCr3()) {
		return false;
	}

	return true;
}

bool MemoryPage::WriteVirtualMemory(const std::uint64_t DirectoryTable, const std::uint64_t Address, void* Buffer, const std::size_t Size)
{
	if (!DirectoryTable || !Address || !Buffer || !Size)
	{
		return false;
	}

	std::size_t Offset = 0x00;
	std::size_t Value = Size;

	while (Value)
	{
		const std::uint64_t PhysicalAddress = this->GetPhysicalAddress(
			DirectoryTable,
			Offset + Address
		);

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

bool MemoryPage::ReadVirtualMemory(const std::uint64_t DirectoryTable, const std::uint64_t Address, void* Buffer, const std::size_t Size)
{
	if (!DirectoryTable || !Address || !Buffer || !Size) {
		return false;
	}

	std::size_t Offset = 0x00;
	std::size_t Value = Size;

	while (Value)
	{
		const std::uint64_t PhysicalAddress = this->GetPhysicalAddress(DirectoryTable, Offset + Address);

		if (!PhysicalAddress) {
			return false;
		}

		const std::uint64_t Bytes = min(PAGE_SIZE - (PhysicalAddress & 0xFFF), Value);

		this->ReadPhysicalMemory(PhysicalAddress, (void*)((std::uint64_t)Buffer + Offset), Bytes);

		Offset += Bytes;
		Value -= Bytes;
	}

	return true;
}

bool MemoryPage::WritePhysicalMemory(const std::uint64_t PhysicalAddress, void* Buffer, std::size_t Size)
{
	// Setting Page Frame Number
	std::uint64_t PageFrameNumber = this->SetPageFrameNumber(PhysicalAddress >> 12);

	// Reading the data
	this->memmove((void*)this->Buffer, Buffer, Size);

	// Restoring Page Frame Number
	this->SetPageFrameNumber(PageFrameNumber);

	return true;
}

bool MemoryPage::ReadPhysicalMemory(const std::uint64_t PhysicalAddress, void* Buffer, std::size_t Size)
{
	// Setting Page Frame Number
	std::uint64_t PageFrameNumber = this->SetPageFrameNumber(PhysicalAddress >> 12);
	std::uint64_t Offset = PhysicalAddress - ((PhysicalAddress >> 12) * 0x1000);

	this->InvalidateTlbForPage();

	// Reading the data
	this->memmove(Buffer, (void*)(this->Buffer + Offset), Size);

	// Restoring Page Frame Number
	this->SetPageFrameNumber(PageFrameNumber);

	return true;
}

std::uint64_t MemoryPage::GetPhysicalAddress(std::uint64_t DirectoryTable, std::uint64_t VirtualAddress)
{
	std::uint64_t pml4;
	std::uint64_t pdpt;
	std::uint64_t pde;
	std::uint64_t pte;

	DirectoryTable &= ~0xf;
	
	if (!this->ReadPhysicalMemory(8 * ((VirtualAddress >> 39) & 0x1FF) + DirectoryTable, &pml4, sizeof(std::uint64_t))) {
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

std::uint64_t MemoryPage::SetPageFrameNumber(const std::uint64_t PageFrameNumber)
{
	this->memmove(&this->Struct, (void*)Pte, sizeof(MMPTE_HARDWARE));

	// Setting the page frame number
	std::uint64_t Previous = this->Struct.PageFrameNumber;
	this->Struct.PageFrameNumber = PageFrameNumber;
	this->Struct.Global = 0;

	// Writing the pte
	this->memmove((void*)(this->Pte), &this->Struct, sizeof(MMPTE_HARDWARE));

	return Previous;
}

void MemoryPage::InvalidateTlbForPage()
{
	char Buffer[0x1000];
	for (std::uint64_t Offset = NULL; Offset < (0x1000 * 1024); Offset += 0x1000) {
		this->memmove(Buffer, (void*)(0xfffff80584320000 + Offset), 0x1000);
	}
}

std::uint64_t MemoryPage::GetProcess(const char* Name)
{
	// Getting system process
	std::uint64_t SystemProcess = this->GetSystemProcess();

	if (!SystemProcess) {
		return NULL;
	}

	// Getting system cr3
	std::uint64_t SystemCr3 = this->GetSystemCr3();

	if (!SystemCr3) {
		return NULL;
	}

	// Setting up our values
	std::uint64_t LinkStart = SystemProcess + this->OffsetPacket.ActiveProcessLinks;
	std::uint64_t Flink = LinkStart;

	while (Flink)
	{
		// Reading the forward link to the next process
		this->ReadVirtualMemory(SystemCr3, Flink, &Flink, sizeof(std::uint64_t));

		// Calculating the process by removing the process link offset
		std::uint64_t EProcess = Flink - this->OffsetPacket.ActiveProcessLinks;

		// Reading the size of the process
		std::uint64_t VirtualSize = NULL;
		this->ReadVirtualMemory(SystemCr3, EProcess + this->OffsetPacket.VirtualSize, &VirtualSize, sizeof(std::uint64_t));

		// Validating the size of the process
		if (!VirtualSize) {
			continue;
		}

		// Reading the ImageFileName of the Process
		char ProcessName[16] = { };
		this->ReadVirtualMemory(SystemCr3, EProcess + this->OffsetPacket.ImageFileName, &Name, sizeof(Name));

		if (!strcmp(ProcessName, Name)) {
			return EProcess;
		}
	}

	return NULL;
}

std::uint64_t MemoryPage::GetSystemProcess()
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

std::uint64_t MemoryPage::GetSystemCr3()
{
	BYTE Buffer[0x1000];
	for (std::uint64_t Index = 0; Index < 100; Index++)
	{
		this->ReadPhysicalMemory(0x1000 + (Index * 0x1000), Buffer, sizeof(Buffer));

		if (0x00000001000600E9 ^ (0xffffffffffff00ff & *(std::uint64_t*)(Buffer))) {
			continue;
		}

		if (0xfffff80000000000 ^ (0xfffff80000000000 & *(std::uint64_t*)(Buffer + 0x70))) {
			continue;
		}

		if (0xffffff0000000fff & *(std::uint64_t*)(Buffer + 0xA0)) {
			continue;
		}

		return *(std::uint64_t*)(Buffer + 0xA0);
		break;
	}

	return NULL;
}
