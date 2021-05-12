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
        static int versionMajor = 2;
        static int versionMinor = 0;
        static int versionRevision = 0;

        enum EncDec
        {
            Auto,
            Decrypt,
            Encrypt
        }

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
            Console.WriteLine("Usage: ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("    EncDecFile ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("-d ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("filename");
            Console.Write(" [");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("-o ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("outputfile");
            Console.WriteLine("]");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("    EncDecFile ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("-e ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("filename");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" [");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("-o ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("outputfile");
            Console.WriteLine("]");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("    EncDecFile ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("-a ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("filename");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" [");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("-o ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("outputfile");
            Console.WriteLine("]");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("Options:");
            Console.WriteLine("    -d filename   Decrypts config file filename.");
            Console.WriteLine("    -e filename   Encrypts config file filename.");
            Console.WriteLine("    -a filename   Auto encrypt or decrypt filename.");
            Console.WriteLine("                  If filename is encrypted it is decrypted, and if it is plain text it is encrypted.");
            Console.WriteLine("    -o outputfile Write output to outputfile.");
            Console.WriteLine("If no outputfile is given with -o, output file will be auto named.");
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.Write("Third ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("3");
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine("ye Software Inc. (c) 2021");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Version: {0}.{1}.{2}. ", versionMajor, versionMinor, versionRevision);
        }

        /*
         * Create automatic outputFilena if none given, if given, return it.
         */
        static string createOutputFilename(string inputFilename, string outputFilename)
        {
            if (null == outputFilename)
            {
                string ext = null;

                outputFilename = inputFilename + "_encdec";

                int numExt = 0;
                do
                {
                    ext = numExt.ToString();
                    ++numExt;
                } while (File.Exists(outputFilename + ext));
                outputFilename = outputFilename + ext;
            }

            return outputFilename;
        }

        static int processFile(EncDec encDec, string inputFilename, string outputFilename)
        {
            string[] lines = File.ReadAllLines(inputFilename);
            string connectionString = null;

            bool foundAdd = false;
            int foundAddAt = 0;
            bool foundConnectionString = false;
            int foundConnectionStringAt = 0;

            int foundStringAt = 0;
            int numEncrypted = 0;
            int numDecrypted = 0;
            int numOther = 0;

            outputFilename = createOutputFilename(inputFilename, outputFilename);

            printInfo("Output File: ", outputFilename);

            using (System.IO.StreamWriter outputFile = new System.IO.StreamWriter(outputFilename)) {
                foundAdd = false;
                foundConnectionString = false;


                if (encDec == EncDec.Auto)
                {
                    printInfo("Action: ", "Automatic detection (Auto)");
                }
                if (encDec == EncDec.Decrypt)
                {
                    printInfo("Action: ", "Decrypting");
                }
                if (encDec == EncDec.Encrypt)
                {
                    printInfo("Action: ", "Encrypting");
                }

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write("Processing: ");
                Console.ForegroundColor = ConsoleColor.White;

                foreach (string line in lines) {
                    /* You need to look for 'add' and after a 
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

                            if (encDec == EncDec.Auto)
                            {
                                if (connectionString.Contains(";"))
                                {
                                    // If the connection string has a ; it is not encrypted, so we will encrypt it
                                    encDec = EncDec.Encrypt;
                                }
                                else
                                {
                                    encDec = EncDec.Decrypt;
                                }
                            }

                            if (encDec == EncDec.Encrypt)
                            {
                                // We want to encrypt
                                result = enc.Encrypt(connectionString, true);
                                ++numEncrypted;
                                Console.ForegroundColor = ConsoleColor.Magenta;
                                Console.Write("e");
                                Console.ForegroundColor = ConsoleColor.White;
                            }
                            else
                            {
                                // We want to decrypt
                                result = enc.Decrypt(connectionString, true);
                                ++numDecrypted;
                                Console.ForegroundColor = ConsoleColor.Magenta;
                                Console.Write("d");
                                Console.ForegroundColor = ConsoleColor.White;
                            }

                            // write line to output file
                            // line1 + connectionString + ending

                            string str1 = line.Substring(0, foundStringAt + 1);
                            string str2 = result;
                            string str3 = line.Substring(foundStringAt + connectionString.Length + 1,
                                (line.Length - (foundStringAt + connectionString.Length + 1)));

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

        static string getInputFilename(string[] args)
        {
            if (args.Length < 2 || args.Length > 4 || args.Length == 3)
            {
                // If not 2 or 4 arguments, get out
                return null;
            }
            // You MUST have 2 or 4 arguments
            if (args[0].Equals("-d", StringComparison.InvariantCulture) 
                || args[0].Equals("-e", StringComparison.InvariantCulture)
                || args[0].Equals("-a", StringComparison.InvariantCulture))
            {
                // following is the inputFilename
                return args[1];
            }
            if (args.Length == 4)
            {
                // If we have 4 arguments, the input file could be the second argument
                if (args[2].Equals("-d", StringComparison.InvariantCulture) 
                    || args[2].Equals("-e", StringComparison.InvariantCulture)
                    || args[2].Equals("-a", StringComparison.InvariantCulture))
                {
                    // following is the inputFilename
                    return args[3];
                }
            }
            return null;
        }

        static string getOutputFilename(string[] args)
        {
            if (args.Length < 2 || args.Length > 4 || args.Length == 3)
            {
                // If not 2 or 4 arguments, get out
                return null;
            }
            // You MUST have 4 arguments, but -o can be 2nd or 4th
            if (args[0].Equals("-o", StringComparison.InvariantCulture))
            {
                // following is the outputFilename
                return args[1];
            }
            if (args.Length == 4)
            {
                // If we have 4 arguments, the output file could be the second argument
                if (args[2].Equals("-o", StringComparison.InvariantCulture))
                {
                    // following is the outputFilename
                    return args[3];
                }
            }
            return null;
        }

        static EncDec getEncrypt(string[] args)
        {
            if (args.Length < 2 || args.Length > 4 || args.Length == 3)
            {
                // If not 2 or 4 arguments, get out
                return EncDec.Auto;
            }
            // You MUST have 2 or 4 arguments
            if (args[0].Equals("-d", StringComparison.InvariantCulture) 
                || args[0].Equals("-e", StringComparison.InvariantCulture)
                || args[0].Equals("-a", StringComparison.InvariantCulture))
            {
                if (args[0].Equals("-e", StringComparison.InvariantCulture))
                {
                    return (EncDec.Encrypt);
                }
                if (args[0].Equals("-d", StringComparison.InvariantCulture))
                {
                    return (EncDec.Decrypt);
                }
                if (args[0].Equals("-a", StringComparison.InvariantCulture))
                {
                    return (EncDec.Auto);
                }
            }
            if (args.Length == 4)
            {
                // If we have 4 arguments, the input file could be the second argument
                if (args[2].Equals("-d", StringComparison.InvariantCulture) 
                    || args[2].Equals("-e", StringComparison.InvariantCulture)
                    || args[2].Equals("-a", StringComparison.InvariantCulture))
                {
                    if (args[2].Equals("-e", StringComparison.InvariantCulture))
                    {
                        return (EncDec.Encrypt);
                    }
                    if (args[2].Equals("-d", StringComparison.InvariantCulture))
                    {
                        return (EncDec.Decrypt);
                    }
                    if (args[2].Equals("-a", StringComparison.InvariantCulture))
                    {
                        return (EncDec.Auto);
                    }
                }
            }
            return EncDec.Auto;
        }

        static void Main(string[] args)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();

            string inputFilename = getInputFilename(args);
            string outputFilename = getOutputFilename(args);
            EncDec encDec = getEncrypt(args);

            if (null == inputFilename
                || (args.Length == 4 && null == outputFilename))
            {
                // if we have no filename, or with have 4 args and no output filename, get out.
                usage();
                return;
            }

            if (!File.Exists(inputFilename))
            {
                printError(inputFilename, "EncDecFile", "File does not exist");
                return;
            }
            if (isDirectory(inputFilename))
            {
                printError(inputFilename, "Parameter error", "Path is a directory, should be a filename");
                return;
            }
            if (!GotPermision())
            {
                printError("Permision denied", "EncDecFile", "You need to be part of the gudepssii to run this programme");
                return;
            }
            if (null != outputFilename)
            {
                // If given, check if output file exists
                if (File.Exists(outputFilename))
                {
                    printError(outputFilename, "EncDecFile", "Output file already exists, aborting");
                    return;
                }
            }
            printInfo("Input file: ", inputFilename);
			
            try {
                processFile(encDec, inputFilename, outputFilename);
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
            catch (FileNotFoundException ex) {
                printError(inputFilename, "Error processing file", ex.Message);
            }
            catch (UnauthorizedAccessException ex) {
                printError(outputFilename, "Error creating output file ", ex.Message);
            }
            catch (Exception ex) {
                printError(inputFilename, "Unspecified error processing file", ex.Message);
            }
            return;
        }
    }
}
