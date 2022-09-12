#include <Windows.h>
#include <stdint.h>

void hookfunction()
{
	MessageBoxA(0, "Hello from hook !", "Hooked", 0);
}

void HookIAT(const char* routine_name)
{
	uint64_t process_base = (uint64_t)GetModuleHandleA(0);
	
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)process_base;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(process_base + dos_header->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(process_base + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	
	while (import_descriptor->Name)
	{
		PIMAGE_THUNK_DATA original_first_thunk = (PIMAGE_THUNK_DATA)(process_base + import_descriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(process_base + import_descriptor->FirstThunk);
		
		while (original_first_thunk->u1.AddressOfData)
		{
			PIMAGE_IMPORT_BY_NAME function_name = (PIMAGE_IMPORT_BY_NAME)(process_base + original_first_thunk->u1.AddressOfData );

			if (!strcmp(routine_name, function_name->Name))
			{
				DWORD old_protection, changed_protection;
				VirtualProtect(&firstThunk->u1.Function, sizeof(uint64_t), PAGE_READWRITE, &old_protection);
				firstThunk->u1.Function = (uint64_t)hookfunction;
				VirtualProtect(&firstThunk->u1.Function, sizeof(uint64_t), old_protection, &changed_protection);

				return;
			}
			original_first_thunk++;
			firstThunk++;
		}
		import_descriptor++;
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
		HookIAT("TranslateMessage");
        return 1;
    }
    return 1;
}
