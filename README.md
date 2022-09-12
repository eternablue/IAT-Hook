# Hooking - IAT

## Hooking

Hooking is a technique that enables a user to redirect the execution flow of a program. Most of the time we use function hooking. We will either replace or redirect a function to our own, this is very usefull and has multiple usecases. There are multiple ways of hooking, here we are looking at `IAT Hooking`, it stands for Import Address Table. It consists of replacing the address of a function by our own in a big table which gets filled at runtime. As i stated before in another repo, i recommend you read more about the [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) to understand the IAT parsing part of this of this code. 
Here is a basic diagram of how IAT Hooking works. In this example, the original function is being called after the mallicious code has been executed. In this example we will simply call another function instead of the original one. The advantage of that technique is it doesn't require modifying the body of a function as opposoed to a regular detours .text patch hook which has to change the instructions at the beggining of a function to place a `jmp` for example.

![image](https://2603957456-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-LFEMnER3fywgFHoroYn%2F-LujUxqEwvQ8GVJuyKNY%2F-LulPrP3NUbUY6FD2CpU%2Fimage.png?alt=media&token=75271be1-0a7d-4dd5-ba59-8261615d6ed2)


## Steps for hooking

It's actually way more simple then it sounds, we will proceed internally to make things easier meaning this repo will compile to a DLL that can be injected in the target process using my [LoadLibraryA](https://github.com/eternablue/DLL-LoadLibraryA) or [Manual Mapping](https://github.com/eternablue/DLL-ManualMapper) injectors to inject in the target process. 

First we parse the `PE Headers` of the target process to locate `Import Descriptor` like so :
```cpp
process_base + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
```
We can then loop though each imported module, loop through each function in this module (reason for the nested loops) and find the address of that function that has been filled at runtime. In this example we will hook `TranslateMessage` which is used by Windows to process events on gui's. So once we found the address of that function, we replace it by the address our own function that we defined previously and that exists in the context of the remote process since we are internal. Don't forget to use `VirtualProtect` to ensure you have the permission to write to that location. 

```cpp
VirtualProtect(&firstThunk->u1.Function, sizeof(uint64_t), PAGE_READWRITE, &old_protection);
firstThunk->u1.Function = (uint64_t)hookfunction;
```

## Showcase

As you can see, when notepad calls `TranslateMessage` (pretty much all the time) it will run our hook function which ends up displaying a message box !

![image](https://cdn.discordapp.com/attachments/780153367305256981/1018961690416656504/demo_iat.gif)
