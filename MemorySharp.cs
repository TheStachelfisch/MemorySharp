using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace MemorySharp
{
    public class MemorySharp
    {
        private readonly Process _currentProcess;
        private string _exeName;
        private IntPtr _processHandle;
        private readonly string _processName;

        public MemorySharp(string processName)
        {
            _exeName = processName;
            _processName = processName.Replace(".exe", "");

            try
            {
                _currentProcess = Process.GetProcessesByName(_processName)[0];
            }
            catch (IndexOutOfRangeException e)
            {
                throw new ArgumentException($"No process with name {processName} is currently running");
            }

            SetProcessHandle();
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, long lpAddress, UIntPtr dwSize, uint flNewProtect,
            out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, long lpBaseAddress, byte[] lpBuffer, int nSize,
            uint lpNumberOfBytesRead = 0);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, long lpBaseAddress, byte[] lpBuffer, int nSize,
            uint lpNumberOfBytesWritten = 0);

        public void SetProcessHandle()
        {
            try
            {
                _processHandle = _currentProcess.Handle;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public long GetBaseAddress()
        {
            Process process;

            var module = _currentProcess.Modules.Cast<ProcessModule>().SingleOrDefault(m => string.Equals(m.ModuleName, _exeName, StringComparison.OrdinalIgnoreCase));

            return module.BaseAddress.ToInt64();
        }

        public long GetPointerAddress(long pointer, int[] offset = null)
        {
            var buffer = new byte[8];

            ReadProcessMemory(_processHandle, pointer, buffer, buffer.Length);

            if (offset != null)
            {
                for (var i = 0; i < offset.Length - 1; i++)
                {
                    pointer = BitConverter.ToInt16(buffer, 0) + offset[i];
                    ReadProcessMemory(_processHandle, pointer, buffer, buffer.Length);
                }

                pointer = BitConverter.ToInt64(buffer, 0) + offset[^1];
            }

            return pointer;
        }

        public byte[] ReadByteArray(long address, int size)
        {
            var result = new byte[size];

            try
            {
                uint flNewProtect;
                VirtualProtectEx(_processHandle, address, (UIntPtr) size, 4U, out flNewProtect);
                var bytes = new byte[size];
                ReadProcessMemory(_processHandle, address, bytes, size);
                VirtualProtectEx(_processHandle, address, (UIntPtr) size, flNewProtect, out flNewProtect);
                result = bytes;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

            return result;
        }

        public byte ReadByte(long address)
        {
            var result = new byte();

            try
            {
                result = ReadByteArray(address, 1)[0];
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

            return result;
        }

        public bool ReadBool(long address)
        {
            var result = false;

            try
            {
                result = BitConverter.ToBoolean(ReadByteArray(address, 1), 0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            
            return result;
        }

        public char ReadChar(long address)
        {
            var result = ' ';
            
            try
            {
                result = BitConverter.ToChar(ReadByteArray(address, 1), 0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            
            return result;
        }

        public double ReadDouble(long address)
        {
            double result = 0;

            try
            {
                result = BitConverter.ToDouble(ReadByteArray(address, 8), 0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            
            return result;
        }

        public float ReadFloat(long address)
        {
            float result = 0;

            try
            {
                result = BitConverter.ToSingle(ReadByteArray(address, 4), 0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            
            return result;
        }

        public short ReadInt16(long address)
        {
            short result = 0;

            try
            {
                result = BitConverter.ToInt16(ReadByteArray(address, 2), 0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

            return result;
        }

        public int ReadInt32(long address)
        {
            var result = 0;
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

        public long ReadInt64(long address)
        {
            long result = 0;

            try
            {
                result = BitConverter.ToInt64(ReadByteArray(address, 8), 0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

            return result;
        }

        public ushort ReadUInt16(long address)
        {
            ushort result = 0;

            try
            {
                result = BitConverter.ToUInt16(ReadByteArray(address, 2), 0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            
            return result;
        }

        public uint ReadUInt32(long address)
        {
            uint result = 0;


            try
            {
                result = BitConverter.ToUInt32(ReadByteArray(address, 4), 0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            
            return result;
        }

        public ulong ReadUInt64(long address)
        {
            ulong result = 0;

            try
            {
                result = BitConverter.ToUInt64(ReadByteArray(address, 8), 0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            
            return result;
        }

        public uint ReadUInt(long address)
        {
            uint result = 0;

            try
            {
                BitConverter.ToUInt32(ReadByteArray(address, 4));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            
            return result;
        }

        public int ReadInteger(long address)
        {
            var result = 2;

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

        public short ReadShort(long address)
        {
            short result = 0;

            try
            {
                result = BitConverter.ToInt16(ReadByteArray(address, 2), 0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            
            return result;
        }

        public ushort ReadUShort(long address)
        {
            ushort result = 0;

            try
            {
                result = BitConverter.ToUInt16(ReadByteArray(address, 2), 0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            
            return result;
        }

        public long ReadLong(long address)
        {
            long result = 0;

            try
            {
                result = BitConverter.ToInt64(ReadByteArray(address, 8), 0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            
            return result;
        }

        public ulong ReadULong(long address)
        {
            ulong result = 0;

            try
            {
                result = BitConverter.ToUInt64(ReadByteArray(address, 8), 0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            
            return result;
        }

        public string ReadASCIIString(long address, int size)
        {
            string result = null;

            try
            {
                result = Encoding.ASCII.GetString(ReadByteArray(address, size), 0, size);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            
            return result;
        }

        public string ReadUnicodeString(long address, int size)
        {
            string result = null;

            try
            {
                result = Encoding.Unicode.GetString(ReadByteArray(address, size), 0, size);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            
            return result;
        }

        public void WriteByteArray(long address, byte[] bytes)
        {
            try
            {
                uint flNewProtect = 0U;
                VirtualProtectEx(_processHandle, address, (UIntPtr)bytes.Length, flNewProtect, out flNewProtect);
                WriteProcessMemory(_processHandle, address, bytes, bytes.Length);
                VirtualProtectEx(_processHandle, address, (UIntPtr) bytes.Length, flNewProtect, out flNewProtect);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteByte(long address, byte data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteChar(long address, char data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteDouble(long address, double data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteFloat(long address, float data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteInt16(long address, short data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteInt32(long address, int data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteInt64(long address, long data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteInt(long address, int data)
        {
            try
            { 
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteLong(long address, long data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteBool(long address, bool data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteShort(long address, short data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteASCIIString(long address, string data)
        {
            try
            { 
                WriteByteArray(address, Encoding.ASCII.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteUnicodeString(long address, string data)
        {
            try
            {
                WriteByteArray(address, Encoding.Unicode.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteUInt16(long address, ushort data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteUInt32(long address, uint data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteUInt64(long address, ulong data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteUInt(long address, uint data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteUShort(long address, ushort data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public void WriteULong(long address, ulong data)
        {
            try
            {
                WriteByteArray(address, BitConverter.GetBytes(data));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
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