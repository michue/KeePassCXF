// SPDX-FileCopyrightText: Copyright (C) 2026 Michael Hüpkes
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using System.Linq;
using System.Text;
using KeePass.DataExchange;
using KeePassCXF;
using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;
using Xunit;

namespace KeePassCXFPlugin.Tests;

public class CxfImportReaderTests
{
	private const string PrivateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgARu_0sCt20EpgVxb4Puq3Ga5VVLpuTY75ngvZlyq3X6hRANCAASmdk1xLsK0oOlhxIPp0d1ZuS0sT9nf6BZtSelhqvLBW0fOL33l_bXgsr_STUHjCLn8l6gcRJwe7OQvbQubZ1dY";
	private const string Prefix = "{\"version\":{\"major\":1,\"minor\":0},\"exporterRpId\":\"exporter.example.com\",\"exporterDisplayName\":\"Exporter\",\"timestamp\":1705228800,\"accounts\":[{\"id\":\"YWNjb3VudA\",\"username\":\"account-user\",\"email\":\"user@example.com\",\"items\":[{\"id\":\"aXRlbQ\",\"creationAt\":1705142400,\"modifiedAt\":1705228800,\"title\":\"Example passkey\",\"credentials\":[";
	private const string Passkey = "{\"type\":\"passkey\",\"credentialId\":\"Y3JlZGVudGlhbElk\",\"rpId\":\"example.com\",\"username\":\"passkey-user\",\"userDisplayName\":\"Display Name\",\"userHandle\":\"dXNlci1oYW5kbGU\",\"key\":\"" + PrivateKey + "\"}";
	private const string Suffix = "]}]}]}";

	[Fact]
	public void Import_CreatesProtectedPasskeyEntryAndMapsAccountFields()
	{
		var database = NewDatabase();
		using (var input = JsonStream(Prefix + Passkey + Suffix))
		{
			new CxfFileFormatProvider().Import(database, input, new TestStatusLogger());

			var entries = database.RootGroup.GetEntries(true);
			Assert.Equal((uint)1, entries.UCount);
			var entry = entries.GetAt(0);
			Assert.Equal("Example passkey", entry.Strings.ReadSafe(PwDefs.TitleField));
			Assert.Equal("account-user", entry.Strings.ReadSafe(PwDefs.UserNameField));
			Assert.Equal("Y3JlZGVudGlhbElk", entry.Strings.ReadSafe("KPEX_PASSKEY_CREDENTIAL_ID"));
			Assert.Equal("example.com", entry.Strings.ReadSafe("KPEX_PASSKEY_RELYING_PARTY"));
			Assert.Equal("passkey-user", entry.Strings.ReadSafe("KPEX_PASSKEY_USERNAME"));
			Assert.Equal("dXNlci1oYW5kbGU", entry.Strings.ReadSafe("KPEX_PASSKEY_USER_HANDLE"));
			Assert.True(entry.Strings.GetSafe("KPEX_PASSKEY_CREDENTIAL_ID").IsProtected);
			Assert.True(entry.Strings.GetSafe("KPEX_PASSKEY_PRIVATE_KEY_PEM").IsProtected);
			Assert.Contains("-----BEGIN PRIVATE KEY-----", entry.Strings.ReadSafe("KPEX_PASSKEY_PRIVATE_KEY_PEM"));
			Assert.Equal("1", entry.Strings.ReadSafe("KPEX_PASSKEY_FLAG_BE"));
			Assert.Equal("1", entry.Strings.ReadSafe("KPEX_PASSKEY_FLAG_BS"));
			Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1705142400).UtcDateTime, entry.CreationTime);
			Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1705228800).UtcDateTime, entry.LastModificationTime);
		}
	}

	[Fact]
	public void Import_MalformedPasskey_DoesNotAddAnyEntries()
	{
		string malformed = Prefix + Passkey.Replace(PrivateKey, "not-base64!") + Suffix;
		var database = NewDatabase();
		using (var input = JsonStream(malformed))
		{
			Assert.Throws<InvalidDataException>(() => new CxfFileFormatProvider().Import(database, input, new TestStatusLogger()));
			Assert.Equal((uint)0, database.RootGroup.GetEntries(true).UCount);
		}
	}

	[Fact]
	public void Import_InvalidDerPrivateKey_DoesNotAddEntries()
	{
		string malformed = Prefix + Passkey.Replace(PrivateKey, "AA") + Suffix;
		var database = NewDatabase();
		using (var input = JsonStream(malformed))
		{
			Assert.Throws<InvalidDataException>(() => new CxfFileFormatProvider().Import(database, input, new TestStatusLogger()));
			Assert.Equal((uint)0, database.RootGroup.GetEntries(true).UCount);
		}
	}

	[Fact]
	public void Import_RejectsUnsupportedMajorVersion()
	{
		string unsupported = Prefix.Replace("\"major\":1", "\"major\":2") + Passkey + Suffix;
		var database = NewDatabase();
		using (var input = JsonStream(unsupported))
		{
			Assert.Throws<InvalidDataException>(() => new CxfFileFormatProvider().Import(database, input, new TestStatusLogger()));
			Assert.Equal((uint)0, database.RootGroup.GetEntries(true).UCount);
		}
	}

	[Fact]
	public void ImportTestData_ImportsEveryExampleWithoutError()
	{
		string fixtureDirectory = Path.Combine(AppContext.BaseDirectory, "TestData", "Import");
		string[] files = Directory.GetFiles(fixtureDirectory, "*.json", SearchOption.AllDirectories)
			.OrderBy(path => path, StringComparer.Ordinal).ToArray();

		foreach (string file in files)
		{
			var database = NewDatabase();
			using (var input = File.OpenRead(file))
			{
				new CxfFileFormatProvider().Import(database, input, new TestStatusLogger());
			}
		}
	}

	[Fact]
	public void Provider_AdvertisesImportAndExport()
	{
		var provider = new CxfFileFormatProvider();

		Assert.True(provider.SupportsImport);
		Assert.True(provider.SupportsExport);
		Assert.True(provider.ImportAppendsToRootGroupOnly);
	}

	private static PwDatabase NewDatabase()
	{
		var database = new PwDatabase();
		database.New(IOConnectionInfo.FromPath("cxf-import-test.kdbx"), new CompositeKey());
		return database;
	}

	private static MemoryStream JsonStream(string json) => new(Encoding.UTF8.GetBytes(json));

	private sealed class TestStatusLogger : IStatusLogger
	{
		public void StartLogging(string strOperation, bool bWriteOperationToLog) { }
		public void EndLogging() { }
		public bool SetProgress(uint uPercent) => true;
		public bool SetText(string strText, LogStatusType lsType) => true;
		public bool ContinueWork() => true;
	}
}
