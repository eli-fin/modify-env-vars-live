# Modify Envs Live
##### This program gets and sets environment variables of any given process (by PID) dynamically

Normally, a process starts with a copy of its parent's environment variables (unless the parent)
specifically set those values.
Some processes handle the Win32 `WM_SETTINGCHANGE` event to update their environment.

However, using this program allows you to change the environment variables of an arbitrary process after it started.

# How it works
It uses a simple DLL injection technique, calls `kernel32!LoadLibrary` to load the a helper library in the remote process,
then calls the dll functions from within that process.
That way, WinAPI functions that allow getting and setting environment can be invoked in the context of the remote process.

This is a pretty simple example and does'nt handle some corner cases.
It relies on the fact the the dll addresses (base addresses, or handles)
are the same for all processes using that specific dll, and therefore, so are the
addresses of the procedures.
This is usually the case, but not always.
In rare cases windows can load the dll code part more than once, of it could have a different
base address within the virtual memory space of the remote process.
This can easily result in an access violation during any of the steps.

This specific issue can be handled by calculation the offset of the proc address from the dll base address
and using the offset value in the remote process.
There are probably some more corner cases though. 

### Notes
- Naturally, the executables might be detected as viruses
- This probably won't work as expected in processes that use anti dll injection techniques
- Use the appropriate executable (for the right bitness) according to the target process,
  or it will fail
- Some processes will cache the variable value, so you might not see the effect you expect


# Project and solution info
The exe project will be doing the injecting with the functions in the dll project.
Both projects output to <solutionDir>/bin/<arch>, which is also what the debug working dir is set to.
The exe expects the the path+name of the dll name to be the same as the exe name will 'Lib' at the end and a dll extension.
e.g. c:\a.exe = c:\aLib.dll

# Tested on win7 with vs2015 and 2010 toolsets
