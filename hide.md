# 一、简介 #
进程隐藏技术包括：
    进程伪装：通过修改指定进程PEB中的路径和命令行信息实现伪装。
    傀儡进程：通过进程挂起，替换内存数据再恢复执行，从而实现创建傀儡进程
    进程隐藏：通过HOOK函数ZwQuerySystemInfornation实现进程隐藏
DLL劫持：通过#pragma comment指令直接转发DLL导出函数或者通过LoadLibrary和GetProcAddress函数获取DLL导出函数并调用
最简单的进程伪装方式就是修改进程名，例如将本地文件名修改成services.exe等系统进程名，从而不被用户发现。进程伪装指的是可以修改任意指定进程信息，即该进程信息再系统中显示的是另一个进程的信息。这样指定进程和伪装进程相同，但实际，执行的操作是不同的。
	__kernel_entry NTSTATUS NtQueryInformationProcess(
  IN HANDLE           ProcessHandle,	//目标进程句柄
  IN PROCESSINFOCLASS ProcessInformationClass,	//获取信息类型
  OUT PVOID           ProcessInformation,	//指向调用应用程序提供的缓冲区的指针，函数将所请求的信息写入该缓冲区。
  IN ULONG            ProcessInformationLength,//ProcessInformation缓冲区大小
  OUT PULONG          ReturnLength //函数返回请求信息的大小
);
# 二、步骤 #
①创建的项目为 RemoteThreadCode，即远程注入代码，其实现的功能是当运行 RemoteThreadCode.exe 时，会在 Explorer.exe 进程中创建一个线程，而这个创建的线程功能实现很简单，就是弹出一个消息框即 OK当双击执行 RemoteThreadCode.exe 时，则会注入一个线程到 Explorer.exe 中当点击确定后，注入到 Explorer.exe 中的线程执行完毕，从而 WaitForSingleObject 等待成功 （见图2）
②打开宿主进程了(我这里打开的是 Explorer.exe 进程),思路是首先变量当前系统下运行的所有的进程,然后遍历获取到得所有的进程的 PID,再调用 ProcessIsExplorer 函数来判断这个进程是否为 Explorer.exe 进程，如果是则记录下这个进程的 PID 就可以了,这样就获得了 Explorer.exe 进程的 PID 
 
③在宿主进程中分配好存储空间，这个存储空间是用来存放我们将要创建的远程线程的线程处理例程。注意，分配的内存必须标记必须带有 EXECUTE,因为分配的这块内存是用来存放线程处理例程的,而线程处理例程必须得执行，所以必须得带有 EXECUTE 标记。因为我们在后面的代码中还必须调用 WriteProcessMemory 来将线程处理例程写入到这块内存中，也需要WRITE 标记。
 

# 三、部分代码 #


include <string>

include <Windows.h>

include <Shlwapi.h>

pragma comment(lib,"ole32.lib")

pragma comment(lib,"shlwapi.lib")

pragma comment(lib,"shell32.lib")

define RTL_MAX_DRIVE_LETTERS 32

define GDI_HANDLE_BUFFER_SIZE32 34

define GDI_HANDLE_BUFFER_SIZE64 60

define GDI_BATCH_BUFFER_SIZE 310



define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

ifndef NT_SUCCESS

define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

endif



if !defined(_M_X64)

define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32

else

define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64

endif



typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];

typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];

typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];



typedef struct _UNICODE_STRING {

USHORT Length;

USHORT MaximumLength;

PWSTR Buffer;

} UNICODE_STRING;

typedef UNICODE_STRING *PUNICODE_STRING;





typedef struct _STRING {

USHORT Length;

USHORT MaximumLength;

PCHAR Buffer;

} STRING;

typedef STRING *PSTRING;



typedef struct _CLIENT_ID {

HANDLE UniqueProcess;

HANDLE UniqueThread;

} CLIENT_ID, *PCLIENT_ID;



typedef struct _CLIENT_ID64 {

ULONG64 UniqueProcess;

ULONG64 UniqueThread;

} CLIENT_ID64, *PCLIENT_ID64;


if defined(_M_X64)

UCHAR SpareBytes[24];

else

UCHAR SpareBytes[36];
endif

ULONG TxFsContext;



GDI_TEB_BATCH GdiTebBatch;

CLIENT_ID RealClientId;

HANDLE GdiCachedProcessHandle;

ULONG GdiClientPID;

ULONG GdiClientTID;

PVOID GdiThreadLocalInfo;

ULONG_PTR Win32ClientInfo[62];

PVOID glDispatchTable[233];

ULONG_PTR glReserved1[29];

PVOID glReserved2;

PVOID glSectionInfo;

PVOID glSection;

PVOID glTable;

PVOID glCurrentRC;

PVOID glContext;



NTSTATUS LastStatusValue;

UNICODE_STRING StaticUnicodeString;

WCHAR StaticUnicodeBuffer[261];



PVOID DeallocationStack;

PVOID TlsSlots[64];

LIST_ENTRY TlsLinks;



PVOID Vdm;

PVOID ReservedForNtRpc;

PVOID DbgSsReserved[2];



ULONG HardErrorMode;

if defined(_M_X64)

PVOID Instrumentation[11];

else

PVOID Instrumentation[9];

endif

GUID ActivityId;



PVOID SubProcessTag;

PVOID EtwLocalData;

PVOID EtwTraceData;

PVOID WinSockData;

ULONG GdiBatchCount;



union

{

PROCESSOR_NUMBER CurrentIdealProcessor;

ULONG IdealProcessorValue;

struct

{

UCHAR ReservedPad0;

UCHAR ReservedPad1;

UCHAR ReservedPad2;

UCHAR IdealProcessor;

};

};



ULONG GuaranteedStackBytes;

PVOID ReservedForPerf;

PVOID ReservedForOle;

ULONG WaitingOnLoaderLock;

PVOID SavedPriorityState;

ULONG_PTR SoftPatchPtr1;

PVOID ThreadPoolData;

PVOID *TlsExpansionSlots;


if defined(_M_X64)

PVOID DeallocationBStore;

PVOID BStoreLimit;

endif

ULONG MuiGeneration;

ULONG IsImpersonating;

PVOID NlsCache;

PVOID pShimData;

ULONG HeapVirtualAffinity;

HANDLE CurrentTransactionHandle;

PTEB_ACTIVE_FRAME ActiveFrame;

PVOID FlsData;



PVOID PreferredLanguages;

PVOID UserPrefLanguages;

PVOID MergedPrefLanguages;

ULONG MuiImpersonation;



union

{

USHORT CrossTebFlags;

USHORT SpareCrossTebBits : 16;

};

union

{

USHORT SameTebFlags;

struct

{

USHORT SafeThunkCall : 1;

USHORT InDebugPrint : 1;

USHORT HasFiberData : 1;

USHORT SkipThreadAttach : 1;

USHORT WerInShipAssertCode : 1;

USHORT RanProcessInit : 1;

USHORT ClonedThread : 1;

USHORT SuppressDebugMsg : 1;

USHORT DisableUserStackWalk : 1;

USHORT RtlExceptionAttached : 1;

USHORT InitialThread : 1;

USHORT SpareSameTebBits : 1;

};

};



PVOID TxnScopeEnterCallback;

PVOID TxnScopeExitCallback;

PVOID TxnScopeContext;

ULONG LockCount;

ULONG SpareUlong0;

PVOID ResourceRetValue;

} TEB, *PTEB;


-----------------
int main(int ,char** )

{



if (init())

{

LPWSTR myPath = TEXT("C:\\Windows\\System32\\calc.exe");

LPWSTR myName = TEXT("calc.exe");



printf("my PID = %d",GetCurrentProcessId());



PEBFake(myPath,myName);



// check

while(1)

{

Sleep(10000);

}

}

return 0;

}
