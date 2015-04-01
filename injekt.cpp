/**
 *   Shell Code Injector v0.1
 *   Copyright (C) 2014, 2015 Odzhan
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <windows.h>
#include <psapi.h>
#include <winnt.h>
#include <Tlhelp32.h>
#include <Winternl.h>

#pragma comment (lib, "advapi32.lib")
#pragma comment (lib, "ntdll.lib")

// external function to create 64-bit thread from 32-bit process
extern "C" HANDLE CreateRemoteThread64 (HANDLE hProcess, 
    LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
    DWORD dwCreationFlags, LPDWORD lpThreadId);
  
void xstrerror (const char fmt[], ...) 
{
  char    *error;
  va_list arglist;
  char    buffer[2048];
  
  va_start (arglist, fmt);
  vsnprintf (buffer, sizeof(buffer) - 1, fmt, arglist);
  va_end (arglist);
  
  FormatMessage (
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL, GetLastError (), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
      (LPSTR)&error, 0, NULL);

  printf ("\n  [ %s : %s\n", buffer, error);
  LocalFree (error);
}

// convert process name to id
DWORD name2pid (char name[])
{
  HANDLE         hSnap;
  PROCESSENTRY32 pe32;
  DWORD          dwId = 0;

  hSnap = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
  
  if (hSnap != INVALID_HANDLE_VALUE) {
    pe32.dwSize = sizeof (PROCESSENTRY32);

    if (Process32First (hSnap, &pe32)) {
      do {
        if (!lstrcmpi (pe32.szExeFile, name)) {
          dwId = pe32.th32ProcessID;
          break;
        }
      } while (Process32Next (hSnap, &pe32));
    }
    CloseHandle (hSnap);
  }
  return dwId;
}

DWORD NtStatusToWin32 (LONG ntstatus)
{
  DWORD oldError;
  DWORD result;
  DWORD br;
  OVERLAPPED o;

  o.Internal = ntstatus;
  o.InternalHigh = 0;
  o.Offset = 0;
  o.OffsetHigh = 0;
  o.hEvent = 0;
  
  oldError = GetLastError();
  
  GetOverlappedResult (NULL, &o, &br, FALSE);
  
  result = GetLastError();
  SetLastError(oldError);
  
  return result;
}

/**
*
* Determines if process token is elevated
* Returns TRUE or FALSE
*
*/
BOOL isElevated (VOID) {
  HANDLE hToken;
  BOOL   bResult = FALSE;
  
  if (OpenProcessToken (GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
    TOKEN_ELEVATION te;
    DWORD dwSize;
    if (GetTokenInformation (hToken, TokenElevation, &te,
        sizeof(TOKEN_ELEVATION), &dwSize)) 
    {
      bResult = te.TokenIsElevated != 0;
    }
    CloseHandle(hToken);
}
  return bResult;
}

/**
*
* Enables or disables a named privilege in token
* Returns TRUE or FALSE
*
*/
BOOL SetPrivilege (char szPrivilege[], BOOL bEnable) {
  HANDLE hToken;
  BOOL   bResult;
  
  bResult = OpenProcessToken(GetCurrentProcess(),
    TOKEN_ADJUST_PRIVILEGES, &hToken);
  
  if (bResult) {
    LUID luid;
    bResult = LookupPrivilegeValue(NULL, szPrivilege, &luid);
    if (bResult) {
      TOKEN_PRIVILEGES tp;
      
      tp.PrivilegeCount = 1;
      tp.Privileges[0].Luid = luid;
      tp.Privileges[0].Attributes = (bEnable) ? SE_PRIVILEGE_ENABLED : 0;

      bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    }
    CloseHandle(hToken);
  }
  return bResult;
}

BOOL inject (DWORD dwId, LPVOID pCode, SIZE_T dwCode)
{
  HANDLE hProc, hThread;
  BOOL   bStatus=FALSE, bRemoteWow64, bLocalWow64;
  LPVOID pMemory;
  SIZE_T written;
  DWORD  old;
  
  printf ("\n  [ opening process id %i", dwId);
  hProc = OpenProcess (PROCESS_ALL_ACCESS, FALSE, dwId);
  if (hProc != NULL)
  {
    printf ("\n  [ allocating %i bytes of RW memory in process", dwCode);
    pMemory=VirtualAllocEx (hProc, 0, dwCode, MEM_COMMIT, PAGE_READWRITE);
    if (pMemory != NULL)
    {
      printf ("\n  [ writing %i bytes of code to 0x%08X", dwCode, pMemory);
      bStatus=WriteProcessMemory (hProc, pMemory, pCode, dwCode, &written);
      if (bStatus) {
        printf ("\n  [ changing memory attributes to RX");
        VirtualProtectEx(hProc, pMemory, dwCode, PAGE_EXECUTE_READ, &old);
        
        IsWow64Process (GetCurrentProcess(), &bLocalWow64);
        IsWow64Process (hProc, &bRemoteWow64);
        
        printf ("\n  [ remote process is %s-bit", bRemoteWow64 ? "32" : "64");
        printf ("\n  [ attach debugger now or set breakpoint on %08X", pMemory);
        printf ("\n  [ press any key to continue . . .");
        fgetc (stdin);
        printf ("\n  [ creating thread");
        
        // if remote process is not wow64 but I am,
        // make switch to 64-bit for thread creation.
        if (!bRemoteWow64 && bLocalWow64) {
          hThread=NULL;
          //DebugBreak ();
          hThread=CreateRemoteThread64 (hProc, NULL, 0,
              (LPTHREAD_START_ROUTINE)pMemory, NULL, NULL, 0);
        } else {
          hThread=CreateRemoteThread (hProc, NULL, 0, 
              (LPTHREAD_START_ROUTINE)pMemory, NULL, NULL, 0);
        }
        if (hThread != NULL)
        {
          printf ("\n  [ waiting for thread to terminate");
          WaitForSingleObject (hThread, INFINITE); 
          CloseHandle (hThread);
        } else {
          xstrerror ("CreateRemoteThread");
        }
      }
      VirtualFreeEx (hProc, pMemory, 0, MEM_RELEASE);
    } else {
      xstrerror ("VirtualFreeEx()");
    }
    CloseHandle (hProc);
  } else {
    xstrerror ("OpenProcess (%i)", dwId);
  }
  return bStatus;
}

VOID ConsoleSetBufferWidth (SHORT X) {
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo (GetStdHandle (STD_OUTPUT_HANDLE), &csbi);
  
  if (X <= csbi.dwSize.X) return;
  csbi.dwSize.X = X;
  SetConsoleScreenBufferSize (GetStdHandle (STD_OUTPUT_HANDLE), csbi.dwSize);
}

BOOL FileExists(LPCTSTR szPath)
{
  DWORD dwAttrib = GetFileAttributes(szPath);

  return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
         !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL read_file (char f[], LPVOID &code, SIZE_T &code_size) {
  LPVOID        pData;
  HANDLE        hFile;
  LARGE_INTEGER size;
  DWORD         read;
  BOOL          bStatus=FALSE;
  
  printf ("\n  [ opening %s", f);
  hFile=CreateFile (f, GENERIC_READ, FILE_SHARE_READ,
      0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
  if (hFile != INVALID_HANDLE_VALUE)
  {
    printf ("\n  [ getting size");
    GetFileSizeEx (hFile, &size);
    
    printf ("\n  [ allocating %i bytes of memory for file", size.LowPart);
    pData=HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, size.LowPart);
    if (pData != NULL)
    {
      printf ("\n  [ reading");
      bStatus=ReadFile (hFile, pData, size.LowPart, &read, 0);
      code=pData;
      code_size=read;
    }
    CloseHandle (hFile);
  } else {
    xstrerror ("CreateFile()");
  }
  return bStatus;
}

void usage (void)
{
  printf ("\n  usage: injekt [proc name | proc id] code.bin\n");
  exit (0);
}

int main (int argc, char *argv[])
{
  SIZE_T code_size=0;
  LPVOID code=NULL;
  DWORD  pid=0;
  char   *proc=NULL, *input=NULL;
  int    i;
  char   opt;
  
  ConsoleSetBufferWidth (300);
  
  printf ("\n  code injector v0.1");
  printf ("\n  Copyright (c) 2014, 2015 Odzhan\n\n");
  
  for (i=1; i<argc; i++) {
    if (argv[i][0]=='/' || argv[i][0]=='-') {
      opt=argv[i][1];
      switch (opt) {
        case '?' :
        case 'h' :
        default  : { usage (); break; }
      }
    } else {
      if (FileExists (argv[i])) {
        input=argv[i];
      } else {
        proc=argv[i];
      }
    }
  }
  
  if (proc==NULL) usage ();
  
  if (!isElevated ()) {
    printf ("\n  [ warning: process requires admin privileges for some process\n");
  }
  
  if (!SetPrivilege (SE_DEBUG_NAME, TRUE)) {
    printf ("\n  [ unable to enable debug privilege\n");
  }
  
  // try convert to integer
  pid=strtol (proc, NULL, 10);
  if (pid == 0) {
    // else get id from name
    pid=name2pid (proc);
  }
  
  if (pid != 0)
  {
    if (input != NULL) {
      if (read_file (input, code, code_size)) {
        inject (pid, code, code_size);
      }
      if (code != NULL) {
        HeapFree (GetProcessHeap(), 0, code);
      }
    } else usage();
  } else {
    printf ("\n  [ unable to determine process id for %s\n", proc);
    return 0;
  }  
  return 0;
}
