from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32

# note: https://stackoverflow.com/questions/15172093/python-kernel32-createprocessa-what-is-it-doing
# all string in Python 3.x is in unicode
# in WinAPI all functions
#   ends with 'A' accept asci-strings,
#   ends with 'W' accept unicode-strings

class debugger():
    def __init__(self):
        self.h_process = None  # 句柄
        self.pid = None
        self.debugger_active = False
        self.h_thread = None
        self.context = None
        self.exception = None
        self.exception_address = None
        self.breakpoints = {}
        self.first_breakpoint = True
        self.hardware_breakpoints = {} # 用于跟踪记录当前调试寄存器的使用情况，以便于查询是否存在一个可用于存储断点的槽
        
        # 确定当前系统中默认内存页大小
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize

        self.guarded_page = []
        self.memory_breakpoints = {}

    def load(self, path_to_exe):
        # 参数dwCreationFlags中的标志位控制着进程的创建方式。
        # 若希望新创建的进程独占一个新的控制台窗口，而不是与父进程共用一个控制台，
        # 则加上标志位CREATE_NEW_CONSOLE(=0x00000010)
        creation_flags = DEBUG_PROCESS

        # 实例化之前定义结构体
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()

        # 以下两个成员变量的共同作用下，新建进程将在一个单独的窗体中被显示，
        # 可以通过改变结构体STARTUPINFO中的各成员变量的值来控制debugee进程的行为。
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0

        # 设置结构体STARTUPINFO中的成员变量cb的值，用以表示结构体本身的大小
        startupinfo.cb = sizeof(startupinfo)

        if kernel32.CreateProcessW(path_to_exe, None, None, None, None,
                                   creation_flags, None, None,
                                   byref(startupinfo),
                                   byref(process_information)):
            # 如果是CreateProcessA()，则传参path_to_exe字符串要byte-string
            print("[*] We have successfully launched the process!")
            print("[*] PID: {0}".format(process_information.dwProcessId))
            self.h_process = self.open_process(
                process_information.dwProcessId)  # 保存指向新建进程的有效句柄以供后续进程访问使用
        else:
            print("[*] Error: 0x{:08x}".format(kernel32.GetLastError()))

    def open_process(self, pid):
        '''
        获取进程句柄
        '''
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        return h_process

    def attach(self, pid):
        self.h_process = self.open_process(pid)

        # 试图附加到目标进程，若附加操作失败则输出提示并返回
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
            # self.run() # https://blog.csdn.net/u012763794/article/details/52174275
        else:
            print("[*] Unable to attach to the process.")

    def run(self):
        # 等待发生在debuggee进程中的调试事件
        while self.debugger_active == True:
            self.get_debug_event()

    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            # input("press a key to continue...")
            # self.debugger_active = False
            
            # 获取相关线程的句柄并提取上下文环境信息
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(h_thread=self.h_thread)
            print("Event Code: {0}, Thread ID: {1}".format(debug_event.dwDebugEventCode, debug_event.dwThreadId))
            
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                    print("Access Violation Detected.") # 这就是代码桩
                elif self.exception == EXCEPTION_BREAKPOINT: # 软断点
                    continue_status = self.exception_handler_breakpoint()
                elif self.exception == EXCEPTION_GUARD_PAGE: # 内存断点
                    print("Guard Page Access Detected.")
                elif self.exception == EXCEPTION_SINGLE_STEP: # 硬件断点
                    # print("Single Stepping.")
                    continue_status = self.exception_handler_single_step()

            kernel32.ContinueDebugEvent(debug_event.dwProcessId,
                                        debug_event.dwThreadId,
                                        continue_status) # 调试事件处理完毕，将目标进程恢复至原先的状态

    def exception_handler_breakpoint(self):
        print("[*] Inside the breakpoint handler.")
        print("Exception address: 0x{0:016x}".format(self.exception_address))
        if self.exception_address not in self.breakpoints:
            # Windows系统自身驱动的一个断点引发的事件则跳过
            if self.first_breakpoint:
                self.first_breakpoint = False
                print("[*] Hit the first breakpoint.")
                return DBG_CONTINUE
        else:
            print("[*] Hit user defined breakpoint.")
            self.write_process_memory(self.exception_address, self.breakpoints[self.exception_address])
            self.context = self.get_thread_context(h_thread=self.h_thread)
            self.context.Rip -= 1
            kernel32.SetThreadContext(self.h_thread, byref(self.context))
        
        return DBG_CONTINUE

    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print("[*] Finished debugging. Exiting...")
            return True
        else:
            print("There was an error")
            return False

    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        if h_thread is not None:
            return h_thread
        else:
            print("[*] Could not obtain a vaild thread handle.")
            return False

    def enumerate_thread(self):
        thread_entry = THREADENTRY32()
        thread_list = []
        # 线程枚举，能获取系统进程列表、系统中的线程列表、被加载入某一进程中的所有模块dlls列表、某个进程所属的堆列表
        # 当第一个参数为TH32CS_SNAPTHREAD，则第二个参数没实际意义
        # 该语句获取注册在当前系统快照对象中的所有线程信息，后期再筛选
        # 返回值为指向快照对象的句柄值
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid) 
        if snapshot is not None:
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot, byref(thread_entry))
            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(snapshot, byref(thread_entry))
                
            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            return False

    def get_thread_context(self, thread_id=None, h_thread=None):
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        # 获取线程句柄
        if h_thread is None:
            h_thread = self.open_thread(thread_id)
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        else:
            return False

    def read_process_memory(self, address, length):
        data = ""
        read_buf = create_string_buffer(length)
        count = c_size_t(0)

        if not kernel32.ReadProcessMemory(self.h_process, 
                                            address, 
                                            read_buf, 
                                            length, 
                                            byref(count)):
            return False
        else:
            data += read_buf.raw
            return True

    def write_process_memory(self, address, data):
        count = c_size_t(0)
        length = len(data)
        c_data = c_char_p(data[count.value:])
        kernel32.WriteProcessMemory.argtypes = [c_ulong, 
            c_void_p, c_char_p, c_size_t, c_void_p]
        return kernel32.WriteProcessMemory(self.h_process,
                                            address,
                                            c_data,
                                            length,
                                            byref(count))

    def bp_set(self, address):
        print("[*] Setting breakpoint at: 0x{0:016x}".format(address))
        if address not in self.breakpoints:
            try:
                original_byte = self.read_process_memory(address, 1) # 备份该内存地址上原有的字节值
                self.write_process_memory(address, b"\xCC") # 写入INT3中断指令操作码（len(b"\xCC")为1）
                self.breakpoints[address] = (address, original_byte) # 将设下的断点记录在一个内部的断点列表中
            except Exception as err:
                print("my_err: {0}".format(err)) # argument 2: <class 'OverflowError'>: int too long to convert
                return False
        return True

    def func_resolve(self, dll, function):
        # refer to https://github.com/CoiroTomas/GrayHatPython3-x64/blob/master/src/chapter3/3.4/my_debugger.py
        kernel32.GetModuleHandleA.restype = c_void_p
        kernel32.GetProcAddress.argtypes = [c_void_p, c_void_p]
        kernel32.GetProcAddress.restype = c_void_p
        kernel32.CloseHandle.argtypes = [c_void_p]

        handle = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle, function)
        kernel32.CloseHandle(handle)
        return address

    def bp_set_hw(self, address, length, condition):
        # 检测硬件断点的长度是否有效
        if length not in (1, 2, 4):
            return False
        else:
            length -= 1

        # 检测硬件断点的触发条件是否有效
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False
        
        # 检测是否存在空置的调试寄存器槽
        if 0 not in self.hardware_breakpoints:
            available = 0
        elif 1 not in self.hardware_breakpoints:
            available = 1
        elif 2 not in self.hardware_breakpoints:
            available = 2
        elif 3 not in self.hardware_breakpoints:
            available = 3
        else:
            return False
        
        # 在每一个线程环境下设置调试寄存器
        for thread_id in self.enumerate_thread():
            context = self.get_thread_context(thread_id=thread_id)
            context.Dr7 |= 1 << (available * 2) # 通过设置DR7中相应的标志位来激活断点

            # 在空置的寄存器写入断点
            if available == 0:
                context.Dr0 = address
            elif available == 1:
                context.Dr1 = address
            elif available == 2:
                context.Dr2 = address
            elif available == 3:
                context.Dr3 = address
            
            context.Dr7 |= condition << ((available * 4) + 16) # 设置硬件断点的触发条件

            context.Dr7 |= length << ((available * 4) + 18) # 设置硬件断点的长度

            # 提交设置断点后的线程上下文环境信息
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))

        # 更新内部的硬件断点列表
        self.hardware_breakpoints[available] = (address, length, condition)

        return True

    def exception_handler_single_step(self):
        if self.context.Dr6 & 0x1 and (0 in self.hardware_breakpoints):
            slot = 0
        elif self.context.Dr6 & 0x2 and (1 in self.hardware_breakpoints):
            slot = 1
        elif self.context.Dr6 & 0x4 and (2 in self.hardware_breakpoints):
            slot = 2
        elif self.context.Dr6 & 0x8 and (3 in self.hardware_breakpoints):
            slot = 3
        else:
            continue_status = DBG_EXCEPTION_NOT_HANDLED # 这个INT1中断并非由一个硬件断点引发
        
        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE
        
        print("[*] Hardware breakpoint removed.")
        return continue_status

    def bp_del_hw(self, slot):
        for thread_id in self.enumerate_thread():
            context = self.get_thread_context(thread_id=thread_id)
            context.Dr7 &= ~(1 << (slot * 2)) # 通过重设标志位来移除这个硬件断点
            # 将断点地址清零
            if slot == 0:
                context.Dr0 = 0x0
            elif slot == 1:
                context.Dr1 = 0x0
            elif slot == 2:
                context.Dr2 = 0x0
            elif slot == 3:
                context.Dr3 = 0x0

            context.Dr7 &= ~(3 << ((slot * 4) + 16)) # 清空断点触发条件标志位
            context.Dr7 &= ~(3 << ((slot * 4) + 18)) # 清空断点长度标记位

            # 提交移除断点后的线程上下文环境信息
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))

        del self.hardware_breakpoints[slot] # 将该断点从断点列表中删去
        
        return True

    def bp_set_mem(self, address, size):
        mbi = MEMORY_BASIC_INFORMATION()
        # 找出相关内存断点区域所占据的首个内存页，包含内存断点的首地址
        # 若为返回一个完整的结构体，则返回False
        kernel32.VirtualQueryEx.argtypes = [HANDLE, LPVOID, LPVOID, c_size_t]
        if kernel32.VirtualQueryEx(self.h_process,
                                    address,
                                    byref(mbi),
                                    sizeof(mbi)) < sizeof(mbi):
            return False
        
        current_page = mbi.BaseAddress
        
        # 对整个内存断点区域所覆盖到的所有内存页设置权限
        while current_page <= address + size:
            # 记录这个内存页方便分别开这些保护页 与 OS或debugee进程自设的保护页
            self.guarded_page.append(current_page)
            kernel32.VirtualProtectEx.argtypes = [HANDLE, LPVOID, c_size_t, DWORD, POINTER(c_ulong)]
            old_protection = c_ulong(0)
            if not kernel32.VirtualProtectEx(self.h_process,
                                                current_page,
                                                size,
                                                mbi.Protect | PAGE_GUARD,
                                                byref(old_protection)):
                return False
            # 以系统所设的内存页尺寸为步长单位递增内存断点区域
            current_page += self.page_size

        self.memory_breakpoints[address] = (address, size, mbi)

        return True


if __name__ == "__main__":
    my_debugger = debugger()
    pid = input("Enter the PID of the process to attach to: ")
    my_debugger.attach(int(pid))

    # t_list = my_debugger.enumerate_thread()
    # for t in t_list:
    #     t_context = my_debugger.get_thread_context(t)
    #     print("[*] Dumping registers for thread ID: 0x{0:08x}".format(t))
    #     print("[**] RIP: 0x{0:016x}".format(t_context.Rip))
    #     print("[**] RSP: 0x{0:016x}".format(t_context.Rsp))
    #     print("[**] RBP: 0x{0:016x}".format(t_context.Rbp))
    #     print("[**] RAX: 0x{0:016x}".format(t_context.Rax))
    #     print("[**] RBX: 0x{0:016x}".format(t_context.Rbx))
    #     print("[**] RCX: 0x{0:016x}".format(t_context.Rcx))
    #     print("[**] RDX: 0x{0:016x}".format(t_context.Rdx))
    #     print("[**] END DUMP")

    printf_address = my_debugger.func_resolve(b"msvcrt.dll", b"printf")
    print("[*] Address of printf: 0x{0:016x}".format(printf_address))
    # my_debugger.bp_set(printf_address)
    # my_debugger.bp_set_hw(printf_address, 1, HW_EXECUTE)
    my_debugger.bp_set_mem(printf_address, 1)

    my_debugger.run()
    # 调试事件流大致是
    # 3(CreateProcessInfo)
    # -->6/2(LoadDll/CreateThread)
    # -->1(Exception) # Windows系统自身驱动的一个断点引发，目的是在目标程序被创建或附加后的第一时间给开发者提供一个检查目标进程内部状况的机会
    # -->4/5(ExitThread/ExitProcess) # 预示对应线程正在退出执行
    # 因此重点关注EventCode为1的这个事件，几乎所有重要的调试事件都会借此出现

    my_debugger.detach()
    # my_debugger.load(r"c:/Windows/System32/calc.exe")
