# vehhook - VEH + PAGE_GUARD Function Interception

i wanted to see if i could hook functions without patching a single byte of code. you can!, using vectored exception handling and page guard protection.

this is the result of that.

## what is this?

vehhook is a single-header C++20 library that intercepts function calls on Windows by:

1. setting `PAGE_GUARD` on the memory page containing the target function
2. catching the resulting `STATUS_GUARD_PAGE_VIOLATION` via a Vectored Exception Handler
3. redirecting the instruction pointer to your detour function
4. re-arming the guard page when execution resumes

no inline patches. no jmp hooks. no int3. no trampolines. no code modification at all.

## why does this exist?

most hooking libraries (minhook, detours, etc) work by overwriting the first few bytes of the target function. that's fine for production, but i wanted to understand the exception handling internals of Windows better.

this project is purely educational. it's meant to demonstrate:

- how `PAGE_GUARD` memory protection works
- how Vectored Exception Handling works
- how `STATUS_GUARD_PAGE_VIOLATION` and `STATUS_SINGLE_STEP` interact
- how thread context manipulation works at the exception handler level
- that you can intercept functions without ever touching the original code

## the flow

```
User calls create(target, detour)
            |
            v
      Find target page via VirtualQuery
            |
            v
      Store original page protection
            |
            v
      Apply PAGE_GUARD via VirtualProtect
            |
            v
      Register hook entry
```

at runtime:

```
Target function is called
            |
            v
      CPU hits PAGE_GUARD page
            |
            v
      STATUS_GUARD_PAGE_VIOLATION
            |
            v
      VEH handler fires
            |
            v
      Match RIP to hook target
            |
            v
      Replace RIP with detour
            |
            v
      Set Trap Flag (EFlags |= 0x100)
            |
            v
      Continue execution (retry instruction)
            |
            v
      Detour executes
            |
            v
      STATUS_SINGLE_STEP fires
            |
            v
      Re-apply PAGE_GUARD
            |
            v
      Continue execution
```

## prerequisites

- Windows x64
- MSVC (Visual Studio 2022)
- CMake 3.20+

## building

```cmd
cmake -B build/intermediate -S .
cmake --build build/intermediate --config Debug
```

the test executable ends up in `build\vehhook_test.exe`.

## project structure

```
vehhook/
├── CMakeLists.txt           # root build config
├── src/
│   └── vehhook.h            # the entire library (single header)
├── test/
│   ├── CMakeLists.txt
│   └── test.cc              # automated tests
├── build/
│   ├── vehhook_test.exe     # compiled test binary
│   └── intermediate/        # cmake build artifacts
└── images/
    └── 9FDC8A61-C591-412D-B6A1-E13D35DE64D6.png
```

## basic usage

```cpp
#include "vehhook.h"

static int WINAPI DetourFunc() {
  return 0;
}

void example() {
  auto hook = vehhook::create(TargetFunction, DetourFunc);
  if (!hook.IsValid()) {
    return;
  }

  hook.Enable();

  TargetFunction();

  auto result = vehhook::call_original<int>(hook);

  hook.Disable();
  remove(hook);
}
```

## call_original

since there's no trampoline, `call_original` works by temporarily disabling the hook, calling the original function, then re-enabling it. the RAII scope guard makes sure it gets re-enabled even on early return.

```cpp
static int WINAPI MyDetour(int x) {
  printf("detour: %d\n", x);
  return vehhook::call_original<int>(g_hook, x);
}
```

## multiple hooks per page

if you have three functions on the same page, you can hook all of them. the library tracks each hook individually and only re-arms the page guard when at least one hook on that page is enabled.

## limitations

- **PAGE_GUARD applies to the whole page** - if the target page contains other functions that get called, they'll trigger guard violations too. the handler handles this gracefully (just continues execution), but it means those calls consume the guard and your hook won't fire until the next cycle
- **no trampolines** - use `call_original` instead, which temporarily disables the hook
- **same-page targets** - if your target function is on the same page as your hook management code, setting `PAGE_GUARD` will trigger on your own code. this is expected - just target functions in other DLLs or modules
- **no cross-process support** - VEH is per-process
- **race conditions** - between disabling a hook and calling the original, another thread might sneak in. this is inherent in the approach

## what i learned

- `PAGE_GUARD` is consumed on first access and clears itself. you have to re-apply it every time
- `STATUS_GUARD_PAGE_VIOLATION` fires before the instruction executes, so you can redirect RIP
- the Trap Flag (0x100 in EFlags) causes `STATUS_SINGLE_STEP` after exactly one instruction
- the CPU clears the Trap Flag before delivering the single-step exception, so it only fires once per set
- `VirtualProtect` in an exception handler for the same page that just faulted creates an infinite loop (don't do that)
- SRW lock functions in kernel32 might share a page with your target, consuming the guard before your hook fires

## test output

![test result](images/9FDC8A61-C591-412D-B6A1-E13D35DE64D6.png)
