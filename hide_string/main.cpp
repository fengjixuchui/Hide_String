#include <iostream>

#include "hide_str.hpp"
#include <windows.h>

int main()
{
  // Demo 1
  HIDE_STR2(hide_str, "Hide String1");
  const auto decrypt_string = hide_str.decrypt();
  MessageBoxA(nullptr, reinterpret_cast<LPCSTR>(decrypt_string), reinterpret_cast<LPCSTR>(decrypt_string), MB_OK);
  // free memory
  hide_str.str_free(decrypt_string);
  // Demo 2
  // It is simple like a magic
  MessageBoxA(nullptr, reinterpret_cast<LPCSTR>(HIDE_STR("Привет мир")), reinterpret_cast<LPCSTR>(HIDE_STR("Hide String2")), MB_OK);
  // test for no hide strings
  MessageBoxA(nullptr, "NO Hide String1", "NO Hide String2", MB_OK);
}
