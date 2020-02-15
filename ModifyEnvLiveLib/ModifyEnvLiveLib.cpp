#include <Windows.h>
#include <string>

// Get a string from error code
const std::string __declspec(dllexport) getWinapiErrorMsg(const DWORD err)
{
	LPSTR msgBuffer;

	size_t msgSize = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), // Always get English message
		(LPSTR)&msgBuffer,
		0,
		NULL);

	std::string msg = msgBuffer;
	msg = "Error " + std::to_string(err) + ":\n" + msg;

	LocalFree(msgBuffer);

	return msg;
}

// This is the buffer size the functions expect to have available
// Technically, the limit for environment variables is higher, but this should usually be enough.
// You can always raise it if you need to. This is the only location that needs to be modified.
__declspec(dllexport) const extern int REMOTE_BUFFER_SIZE = 2000 + 1;

// Export all functions as "C", so function names aren't decorated and
// their ProcAddress can be easily obtained
//
// These functions are of ThreadProc type so they can be used to CreateRemoteThread
extern "C"
{
	// Get's an environment variables value
	// p should be a buffer whith the valName in it, and the varValue will be written to it
	// Should be at least as big as REMOTE_BUFFER_SIZE
	// Returns EXIT_FAILURE or EXIT_SUCCESS
	// On failure, will attempt to write error message to p
	DWORD __declspec(dllexport) WINAPI getEnvValue(LPVOID p)
	{
		// Copy var name
		std::string varName = (char*)p;

		// Get value to buffer
		if (!GetEnvironmentVariableA(varName.c_str(), (char*)p, REMOTE_BUFFER_SIZE))
		{
			DWORD err = GetLastError();
			// This usually means the variable exists, but is empty
			if (err == 0)
			{
				strcpy_s((char*)p, REMOTE_BUFFER_SIZE, "[Variable seems to be empty]");
				return EXIT_SUCCESS;
			}

			std::string errMsg = getWinapiErrorMsg(err);
			strcpy_s((char*)p, REMOTE_BUFFER_SIZE, errMsg.c_str());
			return EXIT_FAILURE;
		}
		
		return EXIT_SUCCESS;
	};

	// Set's an environment variables value
	// p should be a buffer whith the valName in it in the format <name>=<value>
	// to delete a variable, pass __DELETE__ as the value
	// Should be at least as big as REMOTE_BUFFER_SIZE
	// Returns EXIT_FAILURE or EXIT_SUCCESS
	// On failure, will attempt to write error message to p
	DWORD __declspec(dllexport) WINAPI setEnvValue(LPVOID p)
	{
		// Copy var name and value
		std::string varNameAndValue = (char*)p;
		// Split name and value
		std::string varName(&varNameAndValue[0], varNameAndValue.find('='));
		std::string varValue(&varNameAndValue[varNameAndValue.find('=')] + 1);

		// This will be passed to SetEnvironmentVariableA
		const char* val = varValue.c_str();

		// Check if to delete variable
		if (varValue == "__DELETE__")
		{
			// NULL can be passed to delete variables
			val = NULL;
		}
		// Attempt to set variable
		if (!SetEnvironmentVariableA(varName.c_str(), val))
		{
			DWORD err = GetLastError();
			std::string errMsg = getWinapiErrorMsg(err);
			strcpy_s((char*)p, REMOTE_BUFFER_SIZE, errMsg.c_str());
			return EXIT_FAILURE;
		}

		return EXIT_SUCCESS;
	};
}