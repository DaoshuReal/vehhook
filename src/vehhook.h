#pragma once

#include <windows.h>

#include <cstdint>
#include <mutex>
#include <type_traits>
#include <unordered_map>

#ifdef VEHHOOK_ENABLE_LOGGING
#include <cstdio>
#define VEHHOOK_LOG(msg)      do { printf("[vehhook] %s\n", msg); } while (0)
#else
#define VEHHOOK_LOG(msg)      ((void)0)
#endif

namespace vehhook {

namespace detail {

struct HookEntry {
  void* target;
  void* detour;
  uintptr_t page_base;
  SIZE_T region_size;
  DWORD original_protect;
  bool enabled;
};

struct PageEntry {
  DWORD original_protect;
  SIZE_T region_size;
  int total_hooks;
  int enabled_hooks;
};

class Manager {
 public:
  static Manager& Get();

  bool AddHook(void* target, void* detour);
  bool RemoveHook(void* target);
  bool EnableHook(void* target);
  bool DisableHook(void* target);
  bool IsEnabled(void* target) const;

 private:
  Manager();
  ~Manager();

  Manager(const Manager&) = delete;
  Manager& operator=(const Manager&) = delete;

  static LONG CALLBACK VexHandler(PEXCEPTION_POINTERS ep);

  LONG HandleGuardPage(CONTEXT& ctx);
  LONG HandleSingleStep(CONTEXT& ctx);

  bool ApplyGuard(uintptr_t page_base, const PageEntry& entry);
  bool RemoveGuard(uintptr_t page_base, const PageEntry& entry);

  mutable std::mutex mutex_;
  std::unordered_map<uintptr_t, HookEntry> hooks_;
  std::unordered_map<uintptr_t, PageEntry> pages_;
  void* handle_;
};

Manager::Manager() : handle_(nullptr) {
  handle_ = AddVectoredExceptionHandler(1, VexHandler);
}

Manager::~Manager() {
  if (handle_) {
    RemoveVectoredExceptionHandler(handle_);
  }

  for (auto& [page_base, entry] : pages_) {
    DWORD old;
    VirtualProtect(reinterpret_cast<void*>(page_base), entry.region_size,
                   entry.original_protect, &old);
  }
}

Manager& Manager::Get() {
  static Manager instance;
  return instance;
}

bool Manager::AddHook(void* target, void* detour) {
  if (!target || !detour) {
    return false;
  }

  if (!handle_) {
    return false;
  }

  std::lock_guard lock(mutex_);

  if (hooks_.find(reinterpret_cast<uintptr_t>(target)) != hooks_.end()) {
    return false;
  }

  MEMORY_BASIC_INFORMATION mbi;
  if (!VirtualQuery(target, &mbi, sizeof(mbi))) {
    return false;
  }

  DWORD protect = mbi.Protect & ~static_cast<DWORD>(PAGE_GUARD);
  if (!(protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
    return false;
  }

  uintptr_t page_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
  SIZE_T region_size = mbi.RegionSize;

  auto page_it = pages_.find(page_base);
  if (page_it == pages_.end()) {
    PageEntry page_entry{};
    page_entry.original_protect = protect;
    page_entry.region_size = region_size;
    page_entry.total_hooks = 0;
    page_entry.enabled_hooks = 0;

    auto [it, inserted] = pages_.emplace(page_base, page_entry);
    if (!inserted) {
      return false;
    }
    page_it = it;
  }

  HookEntry entry{};
  entry.target = target;
  entry.detour = detour;
  entry.page_base = page_base;
  entry.region_size = region_size;
  entry.original_protect = protect;
  entry.enabled = false;

  hooks_.emplace(reinterpret_cast<uintptr_t>(target), entry);
  page_it->second.total_hooks++;

  VEHHOOK_LOG("hook registered");
  return true;
}

bool Manager::RemoveHook(void* target) {
  if (!target) {
    return false;
  }

  std::lock_guard lock(mutex_);

  auto it = hooks_.find(reinterpret_cast<uintptr_t>(target));
  if (it == hooks_.end()) {
    return false;
  }

  auto& entry = it->second;
  auto page_it = pages_.find(entry.page_base);
  if (page_it != pages_.end()) {
    page_it->second.total_hooks--;

    if (entry.enabled) {
      page_it->second.enabled_hooks--;
    }

    if (page_it->second.total_hooks <= 0) {
      RemoveGuard(entry.page_base, page_it->second);
      pages_.erase(page_it);
    } else if (page_it->second.enabled_hooks <= 0) {
      RemoveGuard(entry.page_base, page_it->second);
    }
  }

  hooks_.erase(it);

  VEHHOOK_LOG("hook removed");
  return true;
}

bool Manager::EnableHook(void* target) {
  if (!target) {
    return false;
  }

  std::lock_guard lock(mutex_);

  auto it = hooks_.find(reinterpret_cast<uintptr_t>(target));
  if (it == hooks_.end()) {
    return false;
  }

  auto& entry = it->second;
  if (entry.enabled) {
    return true;
  }

  entry.enabled = true;

  auto page_it = pages_.find(entry.page_base);
  if (page_it != pages_.end()) {
    page_it->second.enabled_hooks++;

    if (page_it->second.enabled_hooks == 1) {
      if (!ApplyGuard(entry.page_base, page_it->second)) {
        entry.enabled = false;
        page_it->second.enabled_hooks--;

        return false;
      }
    }
  }

  VEHHOOK_LOG("hook enabled");
  return true;
}

bool Manager::DisableHook(void* target) {
  if (!target) {
    return false;
  }

  std::lock_guard lock(mutex_);

  auto it = hooks_.find(reinterpret_cast<uintptr_t>(target));
  if (it == hooks_.end()) {
    return false;
  }

  auto& entry = it->second;
  if (!entry.enabled) {
    return true;
  }

  entry.enabled = false;

  auto page_it = pages_.find(entry.page_base);
  if (page_it != pages_.end()) {
    page_it->second.enabled_hooks--;

    if (page_it->second.enabled_hooks <= 0) {
      RemoveGuard(entry.page_base, page_it->second);
    }
  }

  VEHHOOK_LOG("hook disabled");
  return true;
}

bool Manager::IsEnabled(void* target) const {
  if (!target) {
    return false;
  }

  std::lock_guard lock(mutex_);

  auto it = hooks_.find(reinterpret_cast<uintptr_t>(target));
  if (it == hooks_.end()) {
    return false;
  }

  return it->second.enabled;
}

LONG CALLBACK Manager::VexHandler(PEXCEPTION_POINTERS ep) {
  auto& rec = *ep->ExceptionRecord;

  switch (rec.ExceptionCode) {
    case STATUS_GUARD_PAGE_VIOLATION:
      return Get().HandleGuardPage(*ep->ContextRecord);

    case STATUS_SINGLE_STEP:
      return Get().HandleSingleStep(*ep->ContextRecord);

    default:
      return EXCEPTION_CONTINUE_SEARCH;
  }
}

LONG Manager::HandleGuardPage(CONTEXT& ctx) {
  uintptr_t rip = ctx.Rip;

  std::lock_guard lock(mutex_);

  auto it = hooks_.find(rip);
  if (it != hooks_.end()) {
    auto& entry = it->second;
    if (entry.enabled) {
      ctx.Rip = reinterpret_cast<uintptr_t>(entry.detour);
      ctx.EFlags |= 0x100;

      VEHHOOK_LOG("execution redirected");
      return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_EXECUTION;
  }

  for (auto& [page_base, entry] : pages_) {
    if (entry.enabled_hooks > 0 &&
        rip >= page_base &&
        rip < page_base + entry.region_size) {
      return EXCEPTION_CONTINUE_EXECUTION;
    }
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

LONG Manager::HandleSingleStep(CONTEXT& ctx) {
  std::lock_guard lock(mutex_);

  for (auto& [page_base, entry] : pages_) {
    if (entry.enabled_hooks > 0) {
      DWORD old;
      VirtualProtect(reinterpret_cast<void*>(page_base), entry.region_size,
                     entry.original_protect | PAGE_GUARD, &old);
    }
  }

  return EXCEPTION_CONTINUE_EXECUTION;
}

bool Manager::ApplyGuard(uintptr_t page_base, const PageEntry& entry) {
  DWORD old;
  return VirtualProtect(reinterpret_cast<void*>(page_base), entry.region_size,
                        entry.original_protect | PAGE_GUARD, &old) != FALSE;
}

bool Manager::RemoveGuard(uintptr_t page_base, const PageEntry& entry) {
  DWORD old;
  return VirtualProtect(reinterpret_cast<void*>(page_base), entry.region_size,
                        entry.original_protect, &old) != FALSE;
}

}

class Hook {
 public:
  Hook() = default;

  Hook(Hook&& other) noexcept
    : target_(other.target_), detour_(other.detour_) {
    other.target_ = nullptr;
    other.detour_ = nullptr;
  }

  Hook& operator=(Hook&& other) noexcept {
    if (this != &other) {
      target_ = other.target_;
      detour_ = other.detour_;
      other.target_ = nullptr;
      other.detour_ = nullptr;
    }

    return *this;
  }

  Hook(const Hook&) = delete;
  Hook& operator=(const Hook&) = delete;

  bool Enable() {
    return detail::Manager::Get().EnableHook(target_);
  }

  bool Disable() {
    return detail::Manager::Get().DisableHook(target_);
  }

  bool IsEnabled() const {
    return detail::Manager::Get().IsEnabled(target_);
  }

  bool IsValid() const {
    return target_ != nullptr;
  }

  void* target() const { return target_; }
  void* detour() const { return detour_; }

 private:
  friend Hook create(void* target, void* detour);
  friend bool remove(Hook& hook);

  void* target_ = nullptr;
  void* detour_ = nullptr;
};

inline Hook create(void* target, void* detour) {
  Hook hook;

  if (detail::Manager::Get().AddHook(target, detour)) {
    hook.target_ = target;
    hook.detour_ = detour;
  }

  return hook;
}

inline bool remove(Hook& hook) {
  if (!hook.IsValid()) {
    return false;
  }

  bool result = detail::Manager::Get().RemoveHook(hook.target_);
  hook.target_ = nullptr;
  hook.detour_ = nullptr;

  return result;
}

template <typename Ret, typename... Args>
Ret call_original(Hook& hook, Args&&... args) {
  auto fn = reinterpret_cast<Ret (*)(Args...)>(hook.target());

  hook.Disable();

  struct ReEnabler {
    Hook& h;
    ~ReEnabler() { h.Enable(); }
  } re_enabler{hook};

  if constexpr (std::is_void_v<Ret>) {
    fn(std::forward<Args>(args)...);
  } else {
    return fn(std::forward<Args>(args)...);
  }
}

}
