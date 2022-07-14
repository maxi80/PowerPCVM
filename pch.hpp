#pragma once
#include <Windows.h>
#include <iostream>                         // std::cin, std::cout
#include <filesystem>
#include <algorithm>                        // std::all_of
#include <thread>
#include <string>
#include <string_view>
#include <stdexcept>                        // std::overflow_error, std::runtime_error
#include <strsafe.h>                        // strcpy, strcat
#include <stdint.h>                         // intptr_t	uintptr_t
#include <sstream>                          // std::stringstream
#include <fstream>                          // std::basic_fstream
#include <vector>
#include <variant>
#include <optional>                         // std::optional<std::string>, std::optional<bool>
#include <functional>                       // std::function<void(int)>, std::function<void()>
#include <future>
#include <queue>
#include <versionhelpers.h>                 // IsWindows8OrGreater, IsWindows10OrGreater
#include <tchar.h>
#include <assert.h>
#include <utility>                          // type_traits
#include <unordered_map>                    // std::unordered_map<std::string, std::string>
#include <shellapi.h>                       // ShellExecuteA
#include <shlwapi.h>                        // PathFileExistsW
#include <shlobj.h>                         // FOLDERID_Documents, SHGetKnownFolderPath
#include <chrono>
#include <deque>
#include <mutex>
#include <random>
#include <VersionHelpers.h>
#include <bitset>

#define RVA2VA(type, base, rva) (type)((uintptr_t)base + rva)
#define VA2RVA(type, base, va) (type)((uintptr_t)va - (uintptr_t)base)