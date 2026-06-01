#include "vehhook.h"
#include <cstdio>
#include <windows.h>

static int g_detour_count = 0;

static int WINAPI DetourFunc() {
  ++g_detour_count;
  return 0;
}

int main() {
  void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (!page) {
    puts("FAIL: VirtualAlloc");
    return 1;
  }

  uint8_t code[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };
  memcpy(page, code, sizeof(code));

  using Fn = int(*)();
  Fn target_fn = reinterpret_cast<Fn>(page);

  int before = target_fn();
  printf("Before hook: %d\n", before);

  auto hook = vehhook::create(page, DetourFunc);
  if (!hook.IsValid()) {
    puts("FAIL: create()");
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }
  puts("PASS: create()");

  if (!hook.Enable()) {
    puts("FAIL: Enable()");
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }
  puts("PASS: Enable()");

  g_detour_count = 0;
  int intercepted = target_fn();
  printf("Intercepted: %d (detour_count=%d)\n", intercepted, g_detour_count);

  if (g_detour_count != 1) {
    puts("FAIL: detour was not called");
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }
  puts("PASS: interception works");

  hook.Disable();
  g_detour_count = 0;
  int after = target_fn();
  printf("After disable: %d (detour_count=%d)\n", after, g_detour_count);

  if (g_detour_count != 0) {
    puts("FAIL: detour called after disable");
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }
  puts("PASS: disable works");

  if (!hook.Enable()) {
    puts("FAIL: re-Enable()");
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }

  g_detour_count = 0;
  int orig_result = vehhook::call_original<int>(hook);
  printf("call_original: %d (detour_count=%d)\n", orig_result, g_detour_count);

  if (g_detour_count != 0) {
    puts("FAIL: detour called during call_original");
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }

  if (orig_result != 42) {
    puts("FAIL: call_original returned wrong value");
    VirtualFree(page, 0, MEM_RELEASE);
    return 1;
  }
  puts("PASS: call_original works");

  remove(hook);
  VirtualFree(page, 0, MEM_RELEASE);
  puts("PASS: all tests passed");
  return 0;
}
