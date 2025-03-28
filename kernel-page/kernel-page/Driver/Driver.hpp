#pragma once

#include "MemoryPage/MemoryPage.hpp"

#pragma comment(lib, "ntdll.lib")

#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <ntstatus.h>
#include <map>

#pragma pack(push, 1)
typedef struct _Packet
{
	DWORD_PTR Size;
	DWORD_PTR PhysicalAddress;
	HANDLE SectionHandle;
	LPVOID BaseAddress;
	LPVOID ReferenceObject;
};
#pragma pack(pop)

class DriverCommunication {
public:
	DriverCommunication();

	bool Load(const wchar_t* DeviceName);
	void Unload();

	MemoryPage* GenerateMemoryPage();

	template<typename ReturnType, typename ...Arguments>
	ReturnType CallKernelFunction(std::string Export, Arguments... Args)
	{
		// Caching previous context and setting the next context
		const std::uint64_t PreviousContext = this->Context;
		this->Context = this->ExplorerCr3;

		// Reading previous address of function
		std::uint64_t PreviousAddress = NULL;
		this->ReadVirtualMemory(this->Function, &PreviousAddress, sizeof(std::uint64_t));

		if (!PreviousAddress) {
			return { };
		}

		// Getting the export address
		std::uint64_t ExportAddress = this->GetExportAddress(Export);

		if (!ExportAddress) {
			return { };
		}

		// Writing the export address to our function
		this->WriteVirtualMemory(this->Function, &ExportAddress, sizeof(std::uint64_t));

		// Calling the system call to invoke the kernel function we just hooked
		ReturnType(__stdcall * ExportToInvoke)(Arguments...);
		*(void**)&ExportToInvoke = (void*)this->FunctionToCall;
		ReturnType Result = ExportToInvoke(Args...);

		// Writing the export address to our function
		this->WriteVirtualMemory(this->Function, &PreviousAddress, sizeof(std::uint64_t));

		// Writing the context to the previous context
		this->Context = PreviousContext;
		return Result;
	}

	std::uint64_t GetPteAddress(const std::uint64_t Address)
	{
		// Caching previous context and setting the next context
		const std::uint64_t PreviousContext = this->Context;
		this->Context = this->ExplorerCr3;

		// Reading previous address of function
		std::uint64_t PreviousAddress = NULL;
		this->ReadVirtualMemory(this->Function, &PreviousAddress, sizeof(std::uint64_t));

		if (!PreviousAddress) {
			return { };
		}

		// Getting the export address
		std::uint64_t ExportAddress = this->GetSystemImage("ntoskrnl.exe") + 0x26B480;

		if (!ExportAddress) {
			return { };
		}

		// Writing the export address to our function
		this->WriteVirtualMemory(this->Function, &ExportAddress, sizeof(std::uint64_t));

		// Calling the system call to invoke the kernel function we just hooked
		std::uint64_t(__stdcall * ExportToInvoke)(std::uint64_t);
		*(void**)&ExportToInvoke = (void*)this->FunctionToCall;
		std::uint64_t Result = ExportToInvoke(Address);

		// Writing the export address to our function
		this->WriteVirtualMemory(this->Function, &PreviousAddress, sizeof(std::uint64_t));

		// Writing the context to the previous context
		this->Context = PreviousContext;
		return Result;
	}

	bool WriteVirtualMemory(const std::uint64_t Address, void* Buffer, std::size_t Size);
	bool ReadVirtualMemory(const std::uint64_t Address, void* Buffer, std::size_t Size);
	void SetContext(const std::uint64_t Context);
	std::uint64_t GetContext();

	std::uint64_t GetPhysicalAddress(const std::uint64_t VirtualAddress);

	std::uint64_t GetSystemImage(const char* ImageName);
	std::uint64_t GetCr3(const std::uint64_t Process);
	std::uint64_t GetProcess(const char* ProcessName);
	std::uint64_t GetExportAddress(std::string Name);
	std::uint64_t GetSystemCr3();
private:
	bool WritePhysicalMemory(const std::uint64_t Address, void* Buffer, std::size_t Size);
	bool ReadPhysicalMemory(const std::uint64_t Address, void* Buffer, std::size_t Size);

	bool UnmapPhysicalMemory(_Packet* Packet);
	bool MapPhysicalMemory(_Packet* Packet);
	std::uint64_t GetSystemProcess();

	std::map<std::string, std::uint64_t> ExportList;

	std::uint64_t FunctionToCall;
	std::uint64_t ExplorerCr3;
	std::uint64_t Function;
	std::uint64_t Context;
	HANDLE DriverHandle;
};

inline DriverCommunication* Driver = new DriverCommunication();