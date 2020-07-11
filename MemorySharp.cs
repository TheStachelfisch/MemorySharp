using System;
using System.Diagnostics;
using System.Drawing;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace MemorySharp
{
    public class MemorySharp
    {
        private string _processName;
        private Process[] _currentProcess;
        private IntPtr _processHandle;
        
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        
        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);
        
        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, long lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, long lpBaseAddress, byte[] lpBuffer, int nSize, uint lpNumberOfBytesRead = 0);
        
        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, long lpBaseAddress, byte[] lpBuffer, int nSize, uint lpNumberOfBytesWritten = 0);
        
        public MemorySharp(string ProcessName)
        {
            ProcessName = _processName;
        }
        
#pragma warning disable 162
        private bool CheckProcess()
        {
            if (_processName == null) throw new ProcessNotFoundException("You must define a process first"); return false;
            
            _currentProcess = Process.GetProcessesByName(_processName);

            if (_currentProcess.Length == 0) throw new ProcessNotFoundException($"The following process was not found: {_processName}"); return false;

            _processHandle = OpenProcess((uint) VirtualMemoryProtection.PROCESS_ALL_ACCESS, false, _currentProcess[0].Id);
            if(_processHandle == IntPtr.Zero) throw new ProcessNotFoundException($"The following process was not found: {_processName}"); return false;

            return true;
        }
#pragma warning restore 162

        public long GetBaseAddress()
        {
            if (CheckProcess())
            {
                try
                {
                    ProcessModuleCollection moduleCollection = _currentProcess[0].Modules;
                    ProcessModule DLLBaseAddress = null;

                    foreach (ProcessModule i in moduleCollection)
                    {
                        if (i.ModuleName == _processName)
                        {
                            DLLBaseAddress = i;
                        }
                    }

                    return DLLBaseAddress.BaseAddress.ToInt64();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    return 0;
                }
            }

            return 0;
        }
        
        public long GetBaseAddress(string processName)
        {
            if (CheckProcess())
            {
                try
                {
                    ProcessModuleCollection moduleCollection = _currentProcess[0].Modules;
                    ProcessModule DLLBaseAddress = null;

                    foreach (ProcessModule i in moduleCollection)
                    {
                        if (i.ModuleName == processName)
                        {
                            DLLBaseAddress = i;
                        }
                    }

                    return DLLBaseAddress.BaseAddress.ToInt64();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    return 0;
                }
            }

            return 0;
        }

        public long GetPointerAddress(long pointer, int[] offset = null)
        {
            if (CheckProcess())
            {
                byte[] buffer = new byte[8];

                ReadProcessMemory(_processHandle, pointer, buffer, buffer.Length);

                if (offset != null)
                {
                    for (int i = 0; i < (offset.Length - 1); i++)
                    {
                        pointer = BitConverter.ToInt16(buffer, 0) + offset[i];
                        ReadProcessMemory(_processHandle, pointer, buffer, buffer.Length);
                    }
                    
                    pointer = BitConverter.ToInt64(buffer, 0) + offset[offset.Length - 1];
                }

                return pointer;
            }

            return 0;
        }
        
        public byte[] ReadByteArray(long address, int size)
        {
            byte[] result = new byte[0];
            if (CheckProcess())
            {
                try
                {
                    uint flNewProtect;
                    VirtualProtectEx(_processHandle, address, (UIntPtr) size, 4U, out flNewProtect);
                    byte[] bytes = new byte[size];
                    ReadProcessMemory(_processHandle, address, bytes, size, 0U);
                    VirtualProtectEx(_processHandle, address, (UIntPtr)size, flNewProtect, out flNewProtect);
                    result = bytes;
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }
            return result;
        }

        public byte ReadByte(long address)
        {
            byte result = new byte();
            if (CheckProcess())
            {
                try
                {
                    result = ReadByteArray(address, 1)[0];
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public bool ReadBool(long address)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = BitConverter.ToBoolean(ReadByteArray(address, 1), 0);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public Char ReadChar(long address)
        {
            Char result = ' ';
            
            if (CheckProcess())
            {
                try
                {
                    result = BitConverter.ToChar(ReadByteArray(address, 1), 0);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public double ReadDouble(long address)
        {
            double result = 0;
            if (CheckProcess())
            {
                try
                {
                    result = BitConverter.ToDouble(ReadByteArray(address, 8), 0);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }
            
            return result;
        }

        public float ReadFloat(long address)
        {
            float result = 0;
            if (CheckProcess())
            {
                try
                {
                    result = BitConverter.ToSingle(ReadByteArray(address, 4),0);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public Int16 ReadInt16(long address)
        {
            Int16 result = 0;
            if (CheckProcess())
            {
                try
                {
                    result = BitConverter.ToInt16(ReadByteArray(address, 2), 0);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public Int32 ReadInt32(long address)
        {
            Int32 result = 0;
            try
            {
                result = BitConverter.ToInt32(ReadByteArray(address, 4), 0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

            return result;
        }

        public Int64 ReadInt64(long address)
        {
            Int64 result = 0;
            if (CheckProcess())
            {
                try
                {
                    result = BitConverter.ToInt64(ReadByteArray(address, 8), 0);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }
            
            return result;
        }

        public UInt16 ReadUInt16(long address)
        {
            UInt16 result = 0;
            if (CheckProcess())
            {
                try
                {
                    result = BitConverter.ToUInt16(ReadByteArray(address, 2), 0);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public UInt32 ReadUInt32(long address)
        {
            UInt32 result = 0;
            
            if (CheckProcess())
            {
                try
                {
                    result = BitConverter.ToUInt32(ReadByteArray(address, 4), 0);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public UInt64 ReadUInt64(long address)
        {
            UInt64 result = 0;
            if (CheckProcess())
            {
                try
                {
                    result = BitConverter.ToUInt64(ReadByteArray(address, 8), 0);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public uint ReadUInt(long address)
        {
            uint result = 0;
            if (CheckProcess())
            {
                try
                {
                    BitConverter.ToUInt32(ReadByteArray(address, 4));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public int ReadInteger(long address)
        {
            int result = 0;
            if (CheckProcess())
            {
                try
                {
                    result = BitConverter.ToInt32(ReadByteArray(address, 4), 0);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public short ReadShort(long address)
        {
            short result = 0;
            if (CheckProcess())
            {
                try
                {
                    result = BitConverter.ToInt16(ReadByteArray(address, 2), 0);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }
            
            return result;
        }

        public ushort ReadUShort(long address)
        {
            ushort result = 0;
            if (CheckProcess())
            {
                try
                {
                    result = BitConverter.ToUInt16(ReadByteArray(address, 2), 0);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public long ReadLong(long address)
        {
            long result = 0;
            if (CheckProcess())
            {
                try
                {
                    result = BitConverter.ToInt64(ReadByteArray(address, 8), 0);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public ulong ReadULong(long address)
        {
            ulong result = 0;
            if (CheckProcess())
            {
                try
                {
                    result = BitConverter.ToUInt64(ReadByteArray(address, 8), 0);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public string ReadASCIIString(long address, int size)
        {
            string result = null;
            if (CheckProcess())
            {
                try
                {
                    result = System.Text.Encoding.ASCII.GetString(ReadByteArray(address, size), 0, (int) size);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public string ReadUnicodeString(long address, int size)
        {
            string result = null;
            if (CheckProcess())
            {
                try
                {
                    result = System.Text.Encoding.Unicode.GetString(ReadByteArray(address, size), 0, (int) size);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public bool WriteByteArray(long address, byte[] bytes)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    //locAL varIABlE 'FlNewpROteCt' mIghT NoT bE INITiALized bEfore acCeSsiNg
                    uint flNewProtect = 0U;
                    VirtualProtectEx(_processHandle, address, (UIntPtr)bytes.Length, flNewProtect, out flNewProtect);
                    bool flag = WriteProcessMemory(_processHandle, address, bytes, bytes.Length, (uint)bytes.Length);
                    VirtualProtectEx(_processHandle, address, (UIntPtr) bytes.Length, flNewProtect, out flNewProtect);
                    result = flag;
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }

        public bool WriteByte(long address, byte data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteChar(long address, char data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteDouble(long address, double data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteFloat(long address, float data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteInt16(long address, Int16 data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteInt32(long address, Int32 data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteInt64(long address, Int64 data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteInt(long address, int data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteLong(long address, long data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteBool(long address, bool data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteShort(long address, short data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteASCIIString(long address, string data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, Encoding.ASCII.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteUnicodeString(long address, string data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, Encoding.Unicode.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteUInt16(long address, UInt16 data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteUInt32(long address, UInt32 data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteUInt64(long address, UInt64 data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteUInt(long address, uint data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteUShort(long address, ushort data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        public bool WriteULong(long address, ulong data)
        {
            bool result = false;
            if (CheckProcess())
            {
                try
                {
                    result = WriteByteArray(address, BitConverter.GetBytes(data));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }

            return result;
        }
        
        private enum VirtualMemoryProtection : uint
        {
            PAGE_NOACCESS = 1U,
            PAGE_READONLY,
            PAGE_READWRITE = 4U,
            PAGE_WRITECOPY = 8U,
            PAGE_EXECUTE = 16U,
            PAGE_EXECUTE_READ = 32U,
            PAGE_EXECUTE_READWRITE = 64U,
            PAGE_EXECUTE_WRITECOPY = 128U,
            PAGE_GUARD = 256U,
            PAGE_NOCACHE = 512U,
            PROCESS_ALL_ACCESS = 2035711U
        }
    }
}