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
	MEMORY_BASIC_INFORMATION mbi;
	CHAR* base = NULL;



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

		pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSystemProcInfo + pSystemProcInfo->NextEntryOffset);


		//printf("[+] PID => %ld\n", (DWORD)pSystemProcInfo->UniqueProcessId);
		pHandler = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pSystemProcInfo->UniqueProcessId);
		if (pHandler == NULL) {
			wprintf(L"[-] Failed to open handle at %s error code: %ld\n\n", pSystemProcInfo->ImageName.Buffer, GetLastError());
			continue;
		}
		
		//wprintf(L"[+] Image Name => %s\n", pSystemProcInfo->ImageName.Buffer);
		
		while (VirtualQueryEx(pHandler, base, &mbi, sizeof(mbi)) == sizeof(MEMORY_BASIC_INFORMATION)) {
			//printf("[!] Protection %ld\n\n\n", mbi.AllocationProtect);
			if (mbi.AllocationProtect == 32) {
				printf("[+] Potential section with RWX permission: %ld", mbi.AllocationProtect);
			}
			base += mbi.RegionSize;
		}
	}

	CloseHandle(pHandler);
	return 0;
		
}