using System;
using System.IO;
using EncryptorLibrary;

using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;

using System.Security.Principal;

namespace EncDecFile
{
    class Program
    {
        static int versionMajor = 1;
        static int versionMinor = 2;
        static int versionRevision = 0;


        static public string[] GetGroupNames(string domainName, string userName)
        {
            List<string> result = new List<string>();

            using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, domainName)) {
                using (PrincipalSearchResult<Principal> src = UserPrincipal.FindByIdentity(principalContext, userName).GetGroups()) {
                    src.ToList().ForEach(sr => result.Add(sr.SamAccountName));
                }
            }

            return result.ToArray();
        }

        static private bool GotPermision()
        {
            IntPtr logonToken = WindowsIdentity.GetCurrent().Token;
            using (WindowsIdentity windowsId = new WindowsIdentity(logonToken)) {

                string ssid = windowsId.User.ToString();

                //List<string> result = new List<string>();

                foreach (IdentityReference group in windowsId.Groups) {
                    try {
                        //result.Add(group.Translate(typeof(NTAccount)).ToString());
                        string str = group.Translate(typeof(NTAccount)).ToString();
                        if (str.Contains("gudepssii")) {
                            return true;
                        }
                    }
                    catch {
                        return false;
                    }
                }
                return false;
            }
        }

 
        static void printError(string name, string error, string detail)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write(error + ": ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("\'" + name + "\' ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("(" + detail + ")");
            Console.ForegroundColor = ConsoleColor.White;
        }

        static void printInfo(string str1, string str2)
        {
			Console.ForegroundColor = ConsoleColor.Green;
            Console.Write(str1);
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(str2);
            Console.ForegroundColor = ConsoleColor.White;
        }
		
        static void printProgress(string str1, string str2)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(str1);
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write(str2);
            Console.ForegroundColor = ConsoleColor.White;
        }
		
        static void usage()
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Usage: ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("EncDecFile ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("< ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("filename");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(" >");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("Expecting a C# configuration filename to encrypt/decrypt as argument.");
            Console.WriteLine("If connection string is encrypted it will be decrypted and viceversa.");
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.Write("Third ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("3");
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine("ye Software Inc. (c) 2020");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Version: {0}.{1}.{2}. ", versionMajor, versionMinor, versionRevision);
        }

        static int processFile(string filename)
        {
            string[] lines = File.ReadAllLines(filename);
            string connectionString = null;
            string outputFilename = null;
            string ext = null;

            bool foundAdd = false;
            int foundAddAt = 0;
            bool foundConnectionString = false;
            int foundConnectionStringAt = 0;

            int foundStringAt = 0;
            int numEncrypted = 0;
            int numDecrypted = 0;
            int numOther = 0;

            outputFilename = filename + "_encdec";

            int numExt = 0;
            do {
                ext = numExt.ToString();
                ++numExt;
            } while (File.Exists(outputFilename + ext));
            outputFilename = outputFilename + ext;

            using (System.IO.StreamWriter outputFile = new System.IO.StreamWriter(outputFilename)) {
                foundAdd = false;
                foundConnectionString = false;

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write("Processing: ");
                Console.ForegroundColor = ConsoleColor.White;

                foreach (string line in lines) {
                    /* You need to look for 
                     * 'add' and after a 
                     * 'connectionString' the next string after is the connection string 
                     */
                    foundAddAt = line.IndexOf("add", System.StringComparison.Ordinal);
                    if (foundAddAt != -1) {
                        foundAdd = true;
                    }
                    foundConnectionStringAt = line.IndexOf("connectionString", System.StringComparison.Ordinal);
                    if (foundConnectionStringAt != -1
                        && foundConnectionStringAt > foundAddAt
                        && foundAdd == true) {
                        // the connectionString must come after the add
                        foundConnectionString = true;
                    }
                    if (foundConnectionString && foundAdd)
                    {
                        // After finding add and the connections string
                        foundStringAt = line.IndexOf("\"", foundConnectionStringAt,
                                System.StringComparison.Ordinal);
                        if (foundStringAt != -1
                            && foundStringAt > foundConnectionStringAt)
                        {

                            int j = foundStringAt + 1;
                            while (j < line.Length && !line[j].Equals('"')) {
                                //Console.Write(line[j]);
                                j++;
                            }

                            connectionString = line.Substring(foundStringAt + 1,
                                    (j - foundStringAt - 1));

                            Encryptor enc = new Encryptor();
                            string result;

                            if (-1 == connectionString.IndexOf(";", System.StringComparison.Ordinal)) {
                                // Line is encrypted (decrypt it)
                                result = enc.Decrypt(connectionString, true);

                                ++numDecrypted;

                                Console.ForegroundColor = ConsoleColor.Magenta;
                                Console.Write("d");
                                Console.ForegroundColor = ConsoleColor.White;
                            }
                            else {
                                // Line is decrypted (encrypt it)
                                result = enc.Encrypt(connectionString, true);

                                ++numEncrypted;

                                Console.ForegroundColor = ConsoleColor.Magenta;
                                Console.Write("e");
                                Console.ForegroundColor = ConsoleColor.White;
                            }

                            // write line to output file
                            // line1 + connectionString + ending

                            string str1 = line.Substring(0, foundStringAt + 1);
                            string str2 = result;
                            string str3 = line.Substring(foundStringAt + connectionString.Length + 1,
                                (line.Length - (foundStringAt + connectionString.Length + 1)));
                            /*
                            Console.ForegroundColor = ConsoleColor.Magenta;
                            Console.WriteLine(str1);
                            Console.WriteLine(str2);
                            Console.WriteLine(str3);
                            Console.ForegroundColor = ConsoleColor.White;
                            */
                            outputFile.Write(str1);
                            outputFile.Write(str2);
                            outputFile.WriteLine(str3);

                            // Reset values and search for next
                            foundAdd = foundConnectionString = false;
                            foundAddAt = foundConnectionStringAt = foundStringAt = -1;
                            connectionString = null;
                        }
                    }
                    else {
                        // Found nothing, just writ eline
                        outputFile.WriteLine(line);

                        ++numOther;

                        Console.ForegroundColor = ConsoleColor.Magenta;
                        Console.Write(".");
                        Console.ForegroundColor = ConsoleColor.White;
                    }
                }
            }
            Console.WriteLine("");

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("Decrypted: ");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine(numDecrypted + " string" + (numDecrypted == 1 ? "" : "s"));
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("Encrypted: ");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine(numEncrypted + " string" + (numEncrypted == 1 ? "" : "s"));
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("From a total of: ");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine((numEncrypted + numDecrypted + numOther) + " lines");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("Created output file: ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(outputFilename);
            Console.ForegroundColor = ConsoleColor.White;
            return 1;
        }

        static bool isDirectory(string path)
        {
            // get the file attributes for file or directory
            FileAttributes attr = File.GetAttributes(path);

            //detect whether its a directory or file
            if ((attr & FileAttributes.Directory) == FileAttributes.Directory) {
                return true;
            }
            return false;
        }

        static void Main(string[] args)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();

            if (args.Length != 1) {
                usage();
                return;
            }
            
            string filename = args[0];


            if (!File.Exists(filename))
            {
                printError(filename, "EncDecFile", "File does not exist");
                return;
            }
            if (isDirectory(filename))
            {
                printError(filename, "Parameter error", "Path is a directory, should be a filename");
                return;
            }
            if (!GotPermision())
            {
                printError("Permision denied", "EncDecFile", "You need to be part of the gudepssii to run this programm");
                return;
            }
			
			printInfo("Input string: ", filename);
			
            try {
                processFile(filename);
                // the code that you want to measure comes here
				watch.Stop();
				var elapsedMs = watch.ElapsedMilliseconds;
				Console.ForegroundColor = ConsoleColor.Green;
				Console.Write("Finished processing file in ");
				Console.ForegroundColor = ConsoleColor.Yellow;
				if (elapsedMs > 1000)
				{
					Console.Write(Convert.ToString(elapsedMs/1000) + " s");
				}
				else {
					Console.Write(Convert.ToString(elapsedMs) + " ms");
				}
				Console.ForegroundColor = ConsoleColor.Green;
				Console.WriteLine(".");
				Console.ForegroundColor = ConsoleColor.White;
            }
            catch (FileNotFoundException e) {
                printError(filename, "Error processing file", e.Message);
            }
            catch (UnauthorizedAccessException e) {
                printError(filename + "_encdec", "Error creating output file ", e.Message);
            }
            catch (Exception ex) {
                printError(filename, "Unspecified error processing file", ex.Message);
            }
            return;
        }
    }
}
