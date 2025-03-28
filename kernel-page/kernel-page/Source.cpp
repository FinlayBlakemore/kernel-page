#include "Driver/Driver.hpp"
#include <chrono>

int main()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	if (!Driver->Load(L"\\DosDevices\\WinIo")) {
		std::printf(" [-] Loading\n");
		Sleep(-1);
	}

	std::printf(" [+] Loading\n");

	MemoryPage* Memory = Driver->GenerateMemoryPage();

	std::uint64_t MyProcess = Driver->GetProcess(nullptr);
	
	if (!MyProcess) {
		return 1;
	}

	std::uint64_t MyCr3 = Driver->GetCr3(MyProcess);

	if (!MyCr3) {
		return 2;
	}

	std::uint64_t PhysicalAddress1 = NULL;
	std::uint64_t Value1 = 0xDEADBEEF;

	std::uint64_t PhysicalAddress2 = NULL;
	std::uint64_t Value2 = 0xBEEFDEAD;

	std::uint64_t PreviousContext = Driver->GetContext();
	Driver->SetContext(MyCr3);
	{
		PhysicalAddress1 = Driver->GetPhysicalAddress((std::uint64_t)&Value1);
		PhysicalAddress2 = Driver->GetPhysicalAddress((std::uint64_t)&Value2);
	}
	Driver->SetContext(PreviousContext);

	std::printf("Loaded!\n");

	std::uint64_t Result1 = NULL;
	std::uint64_t Result2 = NULL;

	// Start the clock
	auto start = std::chrono::high_resolution_clock::now();

	Memory->ReadVirtualMemory(MyCr3, (std::uint64_t)&Value1, &Result1, sizeof(std::uint64_t));

	// End the clock
	auto end = std::chrono::high_resolution_clock::now();

	// Calculate the duration
	std::chrono::microseconds duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

	// Output the duration
	std::cout << "Execution time: " << duration.count() << " microseconds" << std::endl;

	std::printf("%llx\n", Result1);

	Driver->Unload();

	std::printf(" [+] Page\n");
}