#include <iostream>
#include <string>
#include <Windows.h>

// The following variable and function are defined in ModifyEnvLiveLib.dll
#pragma comment(lib, "ModifyEnvLiveLib")
__declspec(dllimport) const extern int REMOTE_BUFFER_SIZE;
const std::string __declspec(dllimport) getWinapiErrorMsg(const DWORD err);

#ifdef _WIN64
const char* setEnvValue_exported = "setEnvValue";
const char* getEnvValue_exported = "getEnvValue";
#else
// For some reason, only in 32bit exportNames are decoreated (vs2015)
const char* setEnvValue_exported = "_setEnvValue@4";
const char* getEnvValue_exported = "_getEnvValue@4";
#endif

// Globar variables
// Handle to the remote process
HANDLE g_remoteProcess = NULL;
// Handle to dll - same for all processes, only initialized in runSet/runGet functions
HMODULE g_ModifyEnvDll = NULL;

// Function declerations

// Show help
void showHelp();

// Parses arguments
void parseArgs(int argc, char** argv, long& remotePid, std::string& action, std::string& varName, std::string& varValue);

// Get the path of the dll to be loaded on the remote process
const std::string getDllPath();

// Loads the modifyEnv dll in the remote process, so it's functions can be called
// in later threads created in that process.
// Returns winapi error code, of ERROR_SUCCESS if succeeded
DWORD loadDllInRemoteProcess(const std::string dllPath, const long remotePid);

// Unloads the modifyEnv dll in the remote process, to free resources
// Returns winapi error code, of ERROR_SUCCESS if succeeded
DWORD unloadDllInRemoteProcess();

// Returns image path for process handle
// Process handle should have PROCESS_QUERY_INFORMATION permission
std::string getProcessName(const HANDLE p);

// Runs setEnv in remote process
void runSetEnvRemote(std::string varName, std::string varValue);

// Runs getEnv in remote process
void runGetEnvRemote(std::string varName);

void main(int argc, char** argv)
{
	long remotePid;
	std::string action;
	std::string varName;
	std::string varValue;

	parseArgs(argc, argv, remotePid, action, varName, varValue);

	// Load dll and get function pointers
	std::string dllPath = getDllPath();
	if (loadDllInRemoteProcess(dllPath, remotePid) != ERROR_SUCCESS)
	{
		exit(EXIT_FAILURE);
	}

	std::cout << "Found process: " << getProcessName(g_remoteProcess) << std::endl;

	// Set or Get env variable
	if (action == "set")
	{
		runSetEnvRemote(varName, varValue);
	}
	else if (action == "get")
	{
		runGetEnvRemote(varName);
	}

	// Free library
	unloadDllInRemoteProcess();
}

void showHelp()
{
	std::cout
		<< "ModifyEnvLive <pid> [get|set] [name [value]]" << std::endl
		<< "For example: \"ModifyEnvLive 1234 get SystemDrive\"" << std::endl
		<< "             \"or ModifyEnvLive 1234 set SystemDrive D\"" << std::endl
		<< "To delete variables, pass __DELETE__ as the value" << std::endl
		;
}

void parseArgs(int argc, char** argv, long& remotePid, std::string& action, std::string& varName, std::string& varValue)
{
	// Neet at least 3 args + first arg, which is cmdline
	if (argc < 4)
	{
		std::cerr << "Not enough args!" << std::endl << std::endl;
		showHelp();
		exit(EXIT_FAILURE);
	}

	// Parse pid (first argument)
	const char* pidArg = argv[1];
	// Test for non-numeric characters
	while (*pidArg)
	{
		if (*pidArg < '0' || *pidArg > '9')
		{
			std::cerr << "parseArgs: first argument (pid) must be numeric (base 10)" << std::endl;
			exit(EXIT_FAILURE);
		}
		++pidArg;
	}

	long pid = atol(argv[1]);
	remotePid = pid;

	// Parse action (second argument)
	if (argv[2] != std::string("get") && argv[2] != std::string("set"))
	{
		std::cerr << "parseArgs: second argument (action) must be get or set" << std::endl;
		exit(EXIT_FAILURE);
	}
	action = argv[2];

	// Parse varName (third argument)
	varName = argv[3];

	// Parse varValue (fourth argument)
	// Value only needed for set
	if (action == "set")
	{
		if (argc >= 5)
		{
			varValue = argv[4];
		}
		// If no arg supplied, set to empty string
		else
		{
			varValue = "";
		}
	}
}

const std::string getDllPath()
{
	// Get exe path
	char* exePath;
	_get_pgmptr((char**)&exePath);

	// Copy exe path
	char dllPath[MAX_PATH];
	strcpy_s(dllPath, MAX_PATH, exePath);

	// Modify filename end (see readme)
	strcpy_s(dllPath + strlen(dllPath) - 4, strlen("Lib.dll")+1, "Lib.dll");

	// Return
	return std::string(dllPath);
}

DWORD loadDllInRemoteProcess(const std::string dllPath, const long remotePid)
{
	// Get handle to kernel32.dll and LoadLibraryA function
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	if (kernel32 == 0)
	{
		DWORD err = GetLastError();
		std::cerr << "loadDllInRemoteProcess: Error loading kernel32 dll:\n" << getWinapiErrorMsg(err) << std::endl;
		return err;
	}
	FARPROC loadLib = GetProcAddress(kernel32, "LoadLibraryA");
	if (loadLib == 0)
	{
		DWORD err = GetLastError();
		std::cerr << "loadDllInRemoteProcess: Error loading LoadLibraryA function from kernel32 dll:\n" << getWinapiErrorMsg(err) << std::endl;
		return err;
	}

	// Get handle to process
	g_remoteProcess = OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
		FALSE,
		remotePid);
	if (g_remoteProcess == 0)
	{
		DWORD err = GetLastError();
		std::cerr << "loadDllInRemoteProcess: Error accessing remote process (check the pid or try to run as admin):\n" << getWinapiErrorMsg(err) << std::endl;
		return err;
	}

	// Allocate memory in remote process and write dllPath to there, so it can be used
	// to make the remote process load the dll
	LPVOID remoteMem = VirtualAllocEx(g_remoteProcess, NULL, dllPath.size() + 1, MEM_COMMIT, PAGE_READWRITE);
	if (remoteMem == NULL)
	{
		DWORD err = GetLastError();
		std::cerr << "loadDllInRemoteProcess: Error allocating remote memory:\n" << getWinapiErrorMsg(err) << std::endl;
		return err;
	}
	if (!WriteProcessMemory(g_remoteProcess, remoteMem, dllPath.c_str(), dllPath.size() + 1, NULL))
	{
		DWORD err = GetLastError();
		std::cerr << "loadDllInRemoteProcess: Error writing to remote memory):\n" << getWinapiErrorMsg(err) << std::endl;
		return err;
	}

	// Create a remote thread that will call LoadLib on the ModifyEnv dll
	HANDLE remoteThread = CreateRemoteThread(g_remoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLib, remoteMem, 0, NULL);
	if (remoteThread == NULL)
	{
		DWORD err = GetLastError();
		std::cerr << "loadDllInRemoteProcess: Error creating remote thread:\n" << getWinapiErrorMsg(err) << std::endl;
		return err;
	}
	// Wait for thread to close and get exit code
	WaitForSingleObject(remoteThread, INFINITE);
	DWORD threadRetval;
	GetExitCodeThread(remoteThread, &threadRetval);
	if (threadRetval == NULL)
	{
		std::cerr << "loadDllInRemoteProcess: Remote thread failed to load ModifyEnv dll" << std::endl;
		return EXIT_FAILURE;
	}

	// Cleanup
	VirtualFreeEx(g_remoteProcess, remoteMem, 0, MEM_RELEASE);

	return ERROR_SUCCESS;
}

DWORD unloadDllInRemoteProcess()
{
	// Get handle to kernel32.dll and FreeLibrary function
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	if (kernel32 == 0)
	{
		DWORD err = GetLastError();
		std::cerr << "unloadDllInRemoteProcess: Error loading kernel32 dll:\n" << getWinapiErrorMsg(err) << std::endl;
		return err;
	}
	FARPROC freeLib = GetProcAddress(kernel32, "FreeLibrary");
	if (freeLib == 0)
	{
		DWORD err = GetLastError();
		std::cerr << "unloadDllInRemoteProcess: Error loading FreeLibrary function from kernel32 dll:\n" << getWinapiErrorMsg(err) << std::endl;
		return err;
	}

	// Create a remote thread that will call FreeLib on the ModifyEnv dll with the dll handle
	HANDLE remoteThread = CreateRemoteThread(g_remoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)freeLib, g_ModifyEnvDll, 0, NULL);
	if (remoteThread == NULL)
	{
		DWORD err = GetLastError();
		std::cerr << "unloadDllInRemoteProcess: Error creating remote thread:\n" << getWinapiErrorMsg(err) << std::endl;
		return err;
	}

	// Wait for thread to close and get exit code
	WaitForSingleObject(remoteThread, INFINITE);
	DWORD threadRetval;
	GetExitCodeThread(remoteThread, &threadRetval);
	if ((BOOL)threadRetval == FALSE)
	{
		std::cerr << "unloadDllInRemoteProcess: Remote thread failed to free ModifyEnv dll" << std::endl;
		return EXIT_FAILURE;
	}

	return ERROR_SUCCESS;
}

std::string getProcessName(const HANDLE p)
{
	DWORD bufLen = MAX_PATH;
	char buf[MAX_PATH];
	if (!QueryFullProcessImageNameA(p, 0, buf, &bufLen))
	{
		std::cerr << "getProcessName: Error retrieving process image name" << std::endl;
	}
	return std::string(buf);
}

void runSetEnvRemote(std::string varName, std::string varValue)
{
	// Load dll in current process and get function address, which is the same for all processes
	std::string dllPath = getDllPath();
	g_ModifyEnvDll = LoadLibraryA(dllPath.c_str());
	if (g_ModifyEnvDll == 0)
	{
		DWORD err = GetLastError();
		std::cerr << "runSetEnvRemote: Error loading ModifyEnv dll:\n" << getWinapiErrorMsg(err) << std::endl;
		exit(EXIT_FAILURE);
	}
	FARPROC setEnvValue = GetProcAddress(g_ModifyEnvDll, setEnvValue_exported);
	if (setEnvValue == 0)
	{
		DWORD err = GetLastError();
		std::cerr << "runSetEnvRemote: Error finding ModifyEnv dll functions:\n" << getWinapiErrorMsg(err) << std::endl;
		exit(EXIT_FAILURE);
	}

	// Allocate memory in remote process and write argument to there, so it can be used
	// by the function when call from the remote thread
	// Allocation a large buffer, for large variable values
	LPVOID remoteMem = VirtualAllocEx(g_remoteProcess, NULL, REMOTE_BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE);
	if (remoteMem == NULL)
	{
		DWORD err = GetLastError();
		std::cerr << "runSetEnvRemote: Error allocating remote memory:\n" << getWinapiErrorMsg(err) << std::endl;
	}
	// Concatenate name and value to name=value, which is what the function expects
	std::string strToWrite = varName + "=" + varValue;
	if (!WriteProcessMemory(g_remoteProcess, remoteMem, strToWrite.c_str(), strToWrite.size() + 1, NULL))
	{
		DWORD err = GetLastError();
		std::cerr << "runSetEnvRemote: Error writing to remote memory):\n" << getWinapiErrorMsg(err) << std::endl;
	}

	// Create a remote thread that will call getEnv
	HANDLE remoteThread = CreateRemoteThread(g_remoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)setEnvValue, remoteMem, 0, NULL);
	if (remoteThread == NULL)
	{
		DWORD err = GetLastError();
		std::cerr << "runSetEnvRemote: Error creating remote thread:\n" << getWinapiErrorMsg(err) << std::endl;
	}
	// Wait for thread to close and get exit code
	WaitForSingleObject(remoteThread, INFINITE);
	DWORD threadRetval;
	GetExitCodeThread(remoteThread, &threadRetval);

	// Allocate local buffer to copy result to local process
	char* localBuf = new char[REMOTE_BUFFER_SIZE];
	if (!ReadProcessMemory(g_remoteProcess, remoteMem, localBuf, REMOTE_BUFFER_SIZE, NULL))
	{
		DWORD err = GetLastError();
		std::cerr << "runSetEnvRemote: Error reading result from remote memory):\n" << getWinapiErrorMsg(err) << std::endl;
	}

	// If succeeded, print returned value
	if (threadRetval == EXIT_SUCCESS)
	{
		std::cout << "Success" << std::endl;
	}
	// Failed. Print error
	else
	{
		std::cerr << "runSetEnvRemote: Error returned:\n" << localBuf << std::endl;
	}

	// Cleanup
	VirtualFreeEx(g_remoteProcess, remoteMem, 0, MEM_RELEASE);
	delete[] localBuf;
}

void runGetEnvRemote(std::string varName)
{
	// Load dll in current process and get function address, which is the same for all processes
	std::string dllPath = getDllPath();
	g_ModifyEnvDll = LoadLibraryA(dllPath.c_str());
	if (g_ModifyEnvDll == 0)
	{
		DWORD err = GetLastError();
		std::cerr << "runGetEnvRemote: Error loading ModifyEnv dll:\n" << getWinapiErrorMsg(err) << std::endl;
		exit(EXIT_FAILURE);
	}
	FARPROC getEnvValue = GetProcAddress(g_ModifyEnvDll, getEnvValue_exported);
	if (getEnvValue == 0)
	{
		DWORD err = GetLastError();
		std::cerr << "runGetEnvRemote: Error finding ModifyEnv dll functions:\n" << getWinapiErrorMsg(err) << std::endl;
		exit(EXIT_FAILURE);
	}

	// Allocate memory in remote process and write argument to there, so it can be used
	// by the function when call from the remote thread
	// Allocation a large buffer, for large variable values
	LPVOID remoteMem = VirtualAllocEx(g_remoteProcess, NULL, REMOTE_BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE);
	if (remoteMem == NULL)
	{
		DWORD err = GetLastError();
		std::cerr << "runGetEnvRemote: Error allocating remote memory:\n" << getWinapiErrorMsg(err) << std::endl;
	}
	// Write variable name to buffer, which is the argument the function will need
	if (!WriteProcessMemory(g_remoteProcess, remoteMem, varName.c_str(), varName.size() + 1, NULL))
	{
		DWORD err = GetLastError();
		std::cerr << "runGetEnvRemote: Error writing to remote memory):\n" << getWinapiErrorMsg(err) << std::endl;
	}

	// Create a remote thread that will call getEnv
	HANDLE remoteThread = CreateRemoteThread(g_remoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)getEnvValue, remoteMem, 0, NULL);
	if (remoteThread == NULL)
	{
		DWORD err = GetLastError();
		std::cerr << "runGetEnvRemote: Error creating remote thread:\n" << getWinapiErrorMsg(err) << std::endl;
	}
	// Wait for thread to close and get exit code
	WaitForSingleObject(remoteThread, INFINITE);
	DWORD threadRetval;
	GetExitCodeThread(remoteThread, &threadRetval);

	// Allocate local buffer to copy result to local process
	char* localBuf = new char[REMOTE_BUFFER_SIZE];
	if (!ReadProcessMemory(g_remoteProcess, remoteMem, localBuf, REMOTE_BUFFER_SIZE, NULL))
	{
		DWORD err = GetLastError();
		std::cerr << "runGetEnvRemote: Error reading result from remote memory):\n" << getWinapiErrorMsg(err) << std::endl;
	}

	// If succeeded, print returned value
	if (threadRetval == EXIT_SUCCESS)
	{
		std::cout << "VALUE=:\n" << localBuf << std::endl;
	}
	// Failed. Print error
	else
	{
		std::cerr << "runGetEnvRemote: Error returned:\n" << localBuf << std::endl;
	}

	// Cleanup
	VirtualFreeEx(g_remoteProcess, remoteMem, 0, MEM_RELEASE);
	delete[] localBuf;
}
