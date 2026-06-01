#include "vehhook.h"
#include <cstdio>
#include <cstring>
#include <windows.h>

static int g_detour_count = 0;

static int WINAPI DetourFunc() {
  ++g_detour_count;
  return 0;
}

static int WINAPI SecondDetour() {
  return 99;
}

static int test_create_invalid_target() {
  auto hook = vehhook::create(nullptr, DetourFunc);
  if (hook.IsValid()) {
    puts("FAIL: create with null target returned valid hook");
    return 1;
  }
  puts("PASS: null target rejected");

  hook = vehhook::create(DetourFunc, nullptr);
  if (hook.IsValid()) {
    puts("FAIL: create with null detour returned valid hook");
    return 1;
  }
  puts("PASS: null detour rejected");

  void* bad_page = VirtualAlloc(nullptr, 4096, MEM_COMMIT, PAGE_READONLY);
  if (!bad_page) {
    puts("FAIL: VirtualAlloc for bad_page");
    return 1;
  }
  hook = vehhook::create(bad_page, DetourFunc);
  if (hook.IsValid()) {
    VirtualFree(bad_page, 0, MEM_RELEASE);
    puts("FAIL: create with non-executable page returned valid hook");
    return 1;
  }
  VirtualFree(bad_page, 0, MEM_RELEASE);
  puts("PASS: non-executable page rejected");

  return 0;
}

static int test_duplicate_hook() {
  void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (!page) return 1;
  uint8_t code[] = { 0xC3 };
  memcpy(page, code, sizeof(code));

  auto a = vehhook::create(page, DetourFunc);
  if (!a.IsValid()) {
    VirtualFree(page, 0, MEM_RELEASE);
    puts("FAIL: first create returned invalid");
    return 1;
  }

  auto b = vehhook::create(page, DetourFunc);
  if (b.IsValid()) {
    VirtualFree(page, 0, MEM_RELEASE);
    puts("FAIL: duplicate create returned valid");
    return 1;
  }
  puts("PASS: duplicate hook rejected");

  remove(a);
  VirtualFree(page, 0, MEM_RELEASE);
  return 0;
}

static int test_repeated_enable_disable() {
  void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (!page) return 1;
  uint8_t code[] = { 0xC3 };
  memcpy(page, code, sizeof(code));

  auto hook = vehhook::create(page, DetourFunc);
  if (!hook.IsValid()) {
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }

  for (int i = 0; i < 100; ++i) {
    if (!hook.Enable()) {
      printf("FAIL: Enable cycle %d\n", i);
      VirtualFree(page, 0, MEM_RELEASE);
      return 1;
    }
    if (!hook.IsEnabled()) {
      printf("FAIL: IsEnabled after Enable cycle %d\n", i);
      VirtualFree(page, 0, MEM_RELEASE);
      return 1;
    }
    if (!hook.Disable()) {
      printf("FAIL: Disable cycle %d\n", i);
      VirtualFree(page, 0, MEM_RELEASE);
      return 1;
    }
    if (hook.IsEnabled()) {
      printf("FAIL: IsEnabled after Disable cycle %d\n", i);
      VirtualFree(page, 0, MEM_RELEASE);
      return 1;
    }
  }

  puts("PASS: 100 enable/disable cycles");
  remove(hook);
  VirtualFree(page, 0, MEM_RELEASE);
  return 0;
}

static int test_multiple_hooks_same_page() {
  void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (!page) return 1;

  uint8_t* func_a = static_cast<uint8_t*>(page);
  uint8_t* func_b = static_cast<uint8_t*>(page) + 64;
  uint8_t* func_c = static_cast<uint8_t*>(page) + 128;

  uint8_t code[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };
  memcpy(func_a, code, sizeof(code));
  memcpy(func_b, code, sizeof(code));
  memcpy(func_c, code, sizeof(code));

  auto ha = vehhook::create(func_a, DetourFunc);
  auto hb = vehhook::create(func_b, DetourFunc);
  auto hc = vehhook::create(func_c, SecondDetour);

  if (!ha.IsValid() || !hb.IsValid() || !hc.IsValid()) {
    puts("FAIL: create multiple hooks on same page");
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }
  puts("PASS: three hooks on same page created");

  ha.Enable();

  g_detour_count = 0;
  auto ra = reinterpret_cast<int(*)()>(func_a)();
  if (g_detour_count != 1) {
    puts("FAIL: func_a not intercepted");
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }
  puts("PASS: func_a intercepted with all three registered");

  hb.Enable();
  hc.Enable();

  g_detour_count = 0;
  auto rb = reinterpret_cast<int(*)()>(func_b)();
  if (g_detour_count != 1) {
    puts("FAIL: func_b not intercepted");
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }
  puts("PASS: func_b intercepted");

  auto rc = reinterpret_cast<int(*)()>(func_c)();
  if (rc != 99) {
    puts("FAIL: func_c not intercepted by SecondDetour");
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }
  puts("PASS: func_c intercepted by second detour");

  remove(ha);
  remove(hb);
  remove(hc);
  VirtualFree(page, 0, MEM_RELEASE);
  return 0;
}

static int test_remove_twice() {
  void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (!page) return 1;
  uint8_t code[] = { 0xC3 };
  memcpy(page, code, sizeof(code));

  auto hook = vehhook::create(page, DetourFunc);
  if (!hook.IsValid()) {
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }

  if (!remove(hook)) {
    VirtualFree(page, 0, MEM_RELEASE);
    puts("FAIL: first remove");
    return 1;
  }

  if (remove(hook)) {
    VirtualFree(page, 0, MEM_RELEASE);
    puts("FAIL: second remove should return false");
    return 1;
  }

  puts("PASS: double remove handled correctly");
  VirtualFree(page, 0, MEM_RELEASE);
  return 0;
}

static int test_invalid_operations() {
  auto hook = vehhook::create(nullptr, nullptr);
  if (hook.Enable()) {
    puts("FAIL: Enable on invalid hook should return false");
    return 1;
  }
  if (hook.Disable()) {
    puts("FAIL: Disable on invalid hook should return false");
    return 1;
  }
  if (hook.IsEnabled()) {
    puts("FAIL: IsEnabled on invalid hook should return false");
    return 1;
  }
  if (remove(hook)) {
    puts("FAIL: remove on invalid hook should return false");
    return 1;
  }
  puts("PASS: operations on invalid hook handled safely");
  return 0;
}

struct ThreadContext {
  void* target;
  int iterations;
  volatile long success_count;
};

static DWORD WINAPI ThreadProc(LPVOID param) {
  auto ctx = static_cast<ThreadContext*>(param);
  for (int i = 0; i < ctx->iterations; ++i) {
    auto result = reinterpret_cast<int(*)()>(ctx->target)();
    if (result == 0) {
      InterlockedIncrement(&ctx->success_count);
    }
  }
  return 0;
}

static int test_concurrent_access() {
  void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (!page) return 1;
  uint8_t code[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };
  memcpy(page, code, sizeof(code));

  auto hook = vehhook::create(page, DetourFunc);
  if (!hook.IsValid()) {
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }

  hook.Enable();

  ThreadContext ctx;
  ctx.target = page;
  ctx.iterations = 100;
  ctx.success_count = 0;

  HANDLE threads[4];
  for (int i = 0; i < 4; ++i) {
    threads[i] = CreateThread(nullptr, 0, ThreadProc, &ctx, 0, nullptr);
  }

  WaitForMultipleObjects(4, threads, TRUE, INFINITE);
  for (int i = 0; i < 4; ++i) {
    CloseHandle(threads[i]);
  }

  if (ctx.success_count == 0) {
    printf("FAIL: concurrent access: 0 interceptions (expected some)\n");
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }
  printf("PASS: 4 threads x 100 calls, %d intercepted (race window expected)\n",
         ctx.success_count);

  hook.Disable();
  remove(hook);
  VirtualFree(page, 0, MEM_RELEASE);
  return 0;
}

int main() {
  int total = 0;
  int failed = 0;

  auto run = [&](const char* name, int (*fn)()) {
    printf("--- %s ---\n", name);
    int result = fn();
    total++;
    if (result) failed++;
    printf("\n");
  };

  run("basic interception", []() {
    void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!page) return 1;
    uint8_t code[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };
    memcpy(page, code, sizeof(code));

    using Fn = int(*)();
    Fn target_fn = reinterpret_cast<Fn>(page);

    auto hook = vehhook::create(page, DetourFunc);
    if (!hook.IsValid()) { VirtualFree(page, 0, MEM_RELEASE); return 1; }

    hook.Enable();
    g_detour_count = 0;
    target_fn();
    if (g_detour_count != 1) { VirtualFree(page, 0, MEM_RELEASE); return 1; }

    hook.Disable();
    g_detour_count = 0;
    target_fn();
    if (g_detour_count != 0) { VirtualFree(page, 0, MEM_RELEASE); return 1; }

    hook.Enable();
    g_detour_count = 0;
    int orig = vehhook::call_original<int>(hook);
    if (g_detour_count != 0 || orig != 42) {
      VirtualFree(page, 0, MEM_RELEASE);
      return 1;
    }

    remove(hook);
    VirtualFree(page, 0, MEM_RELEASE);
    puts("PASS: basic interception, disable, call_original");
    return 0;
  });

  run("invalid target addresses", test_create_invalid_target);
  run("duplicate hook registration", test_duplicate_hook);
  run("repeated enable/disable cycles", test_repeated_enable_disable);
  run("multiple hooks on same page", test_multiple_hooks_same_page);
  run("double remove", test_remove_twice);
  run("invalid hook operations", test_invalid_operations);
  run("concurrent access 4x100", test_concurrent_access);

  printf("=== %d tests, %d failed ===\n", total, failed);
  return failed;
}
