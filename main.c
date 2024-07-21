#include <Windows.h>
#include <stdio.h>
#include "Struct.h"

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(

	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);


int main() {

	NTSTATUS						STATUS = 0x00;
	fnNtQuerySystemInformation		pNtQuerySystemInformation = NULL;
	WCHAR							wcUpperCaseProcName[MAX_PATH] = { 0x00 };
	ULONG							uArrayLength = 0x00;
	PSYSTEM_PROCESS_INFORMATION		pSystemProcInfo = NULL;
	PBYTE							pTmpPntrVar = NULL;

	HANDLE							pHandler = NULL;
	


	if (!(pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		return -2;
	}

	if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uArrayLength)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH) {
		printf("[!] NtQuerySystemInformation Failed With Error: 0x%0.8X \n", STATUS);
		return -2;
	}

	if (!(pTmpPntrVar = pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uArrayLength))) {
		printf("[!] HeapAlloc Failed With Error: 0x%0.8X \n", STATUS);
		return -2;
	}

	if (!NT_SUCCESS((STATUS = pNtQuerySystemInformation(SystemProcessInformation, pSystemProcInfo, uArrayLength, NULL)))) {
		printf("[!] NtQuerySystemInformation Failed With Error: 0x%0.8X \n", STATUS);
		return -2;
	}

	while (pSystemProcInfo->NextEntryOffset) {

		MEMORY_BASIC_INFORMATION mbi = { 0x0 };
		LPVOID base = 0;

		pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSystemProcInfo + pSystemProcInfo->NextEntryOffset);


		pHandler = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pSystemProcInfo->UniqueProcessId);
		if (pHandler == NULL) {
			//
			// 
			// wprintf(L"[-] Failed to open handle at %s error code: %ld\n\n", pSystemProcInfo->ImageName.Buffer, GetLastError());
			continue;
		}
		
		printf("[+] PID => %ld\n", (DWORD)pSystemProcInfo->UniqueProcessId);
		wprintf(L"[+] Image Name => %s\n", pSystemProcInfo->ImageName.Buffer);
		

		while (VirtualQueryEx(pHandler, base, &mbi, sizeof(mbi)) == sizeof(MEMORY_BASIC_INFORMATION)) {
			//printf("[!] Protection %ld\n\n\n", mbi.AllocationProtect);
			base = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
			if (mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
				printf("[+] Potential section with RWX permission: 0x%lx 0x%p %#7llu bytes\n", mbi.Protect, base, mbi.RegionSize);
			}
		}
		printf("\n");
	}
		CloseHandle(pHandler);

	return 0;
		
}