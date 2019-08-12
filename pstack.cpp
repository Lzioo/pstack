#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <tlhelp32.h>
#include <DBGHELP.h>
#include <stddef.h>

#pragma comment(lib, "dbghelp.lib")


HANDLE g_pHandle;//需要打印栈跟踪的进程句柄

void Init(const DWORD pid)
{
	g_pHandle = OpenProcess(PROCESS_ALL_ACCESS,true,pid);
	if(g_pHandle == INVALID_HANDLE_VALUE){
		printf("OpenProcess error,%u\n",GetLastError());
		exit(0);
	}
	//使用dgbhelp前需要初始化
	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS|SYMOPT_LOAD_LINES);
	SymInitialize(g_pHandle,NULL,true);
}
void Unit()
{
	SymCleanup(g_pHandle);
	CloseHandle(g_pHandle);
}

//打印tid线程的栈
void TraceStack_aux(const DWORD tid)
{
	HANDLE tHandle;//需要打印栈跟踪的线程句柄

	CONTEXT context = {0};

	context.ContextFlags = CONTEXT_ALL;
	tHandle = OpenThread(THREAD_ALL_ACCESS,false,tid);

	if(tHandle == INVALID_HANDLE_VALUE){
		printf("OpenThread error,%u\n",GetLastError());
		return;
	}
	//获得上下文前挂起线程
	if(SuspendThread(tHandle)==-1)
		printf("SuspendThread error,%u\n",GetLastError());
	if(!GetThreadContext(tHandle,&context)){
		printf("GetThreadContext error,%u\n",GetLastError());
		return;
	}
	
	//stackwalk参数
	STACKFRAME sf = {0};
	sf.AddrPC.Offset = context.Rip;
	sf.AddrPC.Mode = AddrModeFlat;
	sf.AddrFrame.Offset = context.Rbp;
	sf.AddrFrame.Mode = AddrModeFlat;
	sf.AddrStack.Offset = context.Rsp;
	sf.AddrStack.Mode = AddrModeFlat;

    DWORD64 dwDisplamentSym = 0;
	DWORD dwDisplacementLine = 0;
	DWORD MachineType = IMAGE_FILE_MACHINE_AMD64;
	int count = 0;

	IMAGEHLP_SYMBOL64 sym = { 0 };
    sym.SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
    sym.MaxNameLength = sizeof(SYMBOL_INFO);

	IMAGEHLP_LINE64 line = {0};
	line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

	//循环获得堆栈里的栈帧
	while(StackWalk64(MachineType, g_pHandle, tHandle,&sf, &context, NULL, 
					  SymFunctionTableAccess64, SymGetModuleBase64, NULL))
	{
		DWORD64 address = sf.AddrPC.Offset;

		//打印符号
		if(!SymGetSymFromAddr64(g_pHandle, address, &dwDisplamentSym, &sym)){
			printf("#%d    %08x+ SymGetSymFromAddr error, %u,%s", count++, GetLastError());
		}else{
			printf("#%d    %08x+ in %s ", count++, sym.Address, sym.Name);
		}
		//打印文件名和行号
		if(!SymGetLineFromAddr64(g_pHandle, address, &dwDisplacementLine, &line)){
			//printf("SymGetLineFromAddr error, %u\n", GetLastError());
			printf("\n");
		}else{
			printf(" from %s.%d\n", line.FileName, line.LineNumber);		
		}
	}
	//恢复线程
	if(ResumeThread(tHandle)==-1)
		printf("ResumeThread error,%u\n",GetLastError());
	CloseHandle(tHandle);
}

//获得pid进程的所有线程
void TraceStack(DWORD pid)

{
	HANDLE	p_snapshot_handle;
	DWORD tid;

	//用toolhelp32获得线程id
	if((p_snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,pid))== INVALID_HANDLE_VALUE){
		printf("CreateToolhelp32Snapshot ERROR:%u\n",GetLastError());
		return;
	}

	THREADENTRY32 te32 = {0};
	te32.dwSize = sizeof(THREADENTRY32);
	if(!Thread32First(p_snapshot_handle,&te32)){
		printf("Thread32First ERROR:%u\n",GetLastError());
		CloseHandle(p_snapshot_handle);
		return;
	}
	else
	{
		do
		{
			//反向匹配
			if(te32.th32OwnerProcessID != pid){
				continue;;
			}
			tid = te32.th32ThreadID;
			printf("\nThread id:%u,OwnnerProcessId = %u\n",tid,pid);
			TraceStack_aux(tid);//传入线程id，打印堆栈
		}while(Thread32Next(p_snapshot_handle,&te32));
	}

	

}
int _tmain(int argc, _TCHAR* argv[])
{
	DWORD	pid;

	if(argc != 2){
		printf("使用方法：pstack <pid>\n");
		return 0;
	}
	pid = wcstoul(argv[1],_T('\0'),0);

	Init(pid);
	TraceStack(pid);
	Unit();
	
	return 0;
}

