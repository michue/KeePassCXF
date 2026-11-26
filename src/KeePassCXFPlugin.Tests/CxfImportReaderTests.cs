// SPDX-FileCopyrightText: Copyright (C) 2026 Michael Hüpkes
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
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
	private const string ItemId = "AAECAwQFBgcICQoLDA0ODw";
	private const string CollectionId = "EBESExQVFhcYGRobHB0eHw";
	private const string Prefix = "{\"version\":{\"major\":1,\"minor\":0},\"exporterRpId\":\"exporter.example.com\",\"exporterDisplayName\":\"Exporter\",\"timestamp\":1705228800,\"accounts\":[{\"id\":\"YWNjb3VudA\",\"username\":\"account-user\",\"email\":\"user@example.com\",\"collections\":[],\"items\":[{\"id\":\"" + ItemId + "\",\"creationAt\":1705142400,\"modifiedAt\":1705228800,\"title\":\"Example passkey\",\"credentials\":[";
	private const string Passkey = "{\"type\":\"passkey\",\"credentialId\":\"Y3JlZGVudGlhbElk\",\"rpId\":\"example.com\",\"username\":\"passkey-user\",\"userDisplayName\":\"Display Name\",\"userHandle\":\"dXNlci1oYW5kbGU\",\"key\":\"" + PrivateKey + "\"}";
	private const string BasicAuth = "{\"type\":\"basic-auth\",\"username\":{\"id\":\"dXNlcm5hbWU\",\"fieldType\":\"string\",\"value\":\"login-user\",\"label\":\"Login name\"},\"password\":{\"id\":\"cGFzc3dvcmQ\",\"fieldType\":\"concealed-string\",\"value\":\"login-password\",\"label\":\"Secret\"}}";
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
			Assert.Equal(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, entry.Uuid.UuidBytes);
			Assert.Equal("Example passkey", entry.Strings.ReadSafe(PwDefs.TitleField));
			Assert.Equal(string.Empty, entry.Strings.ReadSafe(PwDefs.NotesField));
			Assert.Equal(string.Empty, entry.Strings.ReadSafe(PwDefs.UrlField));
			Assert.Equal(string.Empty, entry.Strings.ReadSafe(PwDefs.UserNameField));
			Assert.Equal("Y3JlZGVudGlhbElk", entry.Strings.ReadSafe("KPEX_PASSKEY_CREDENTIAL_ID"));
			Assert.Equal("example.com", entry.Strings.ReadSafe("KPEX_PASSKEY_RELYING_PARTY"));
			Assert.Equal("passkey-user", entry.Strings.ReadSafe("KPEX_PASSKEY_USERNAME"));
			Assert.Equal("dXNlci1oYW5kbGU", entry.Strings.ReadSafe("KPEX_PASSKEY_USER_HANDLE"));
			Assert.Empty(entry.Tags);
			Assert.True(entry.Strings.GetSafe("KPEX_PASSKEY_CREDENTIAL_ID").IsProtected);
			Assert.True(entry.Strings.GetSafe("KPEX_PASSKEY_PRIVATE_KEY_PEM").IsProtected);
			Assert.Contains("-----BEGIN PRIVATE KEY-----", entry.Strings.ReadSafe("KPEX_PASSKEY_PRIVATE_KEY_PEM"));
			Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1705142400).UtcDateTime, entry.CreationTime);
			Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1705228800).UtcDateTime, entry.LastModificationTime);
		}
	}

	[Fact]
	public void Import_MapsBasicAuthCredentialsToPasskeyEntry()
	{
		var database = NewDatabase();
		using (var input = JsonStream(Prefix + BasicAuth + "," + Passkey + Suffix))
			new CxfFileFormatProvider().Import(database, input, new TestStatusLogger());

		var entry = database.RootGroup.GetEntries(true).GetAt(0);
		Assert.Equal("login-user", entry.Strings.ReadSafe(PwDefs.UserNameField));
		Assert.Equal("login-password", entry.Strings.ReadSafe(PwDefs.PasswordField));
		Assert.True(entry.Strings.GetSafe(PwDefs.PasswordField).IsProtected);
		Assert.Equal("passkey-user", entry.Strings.ReadSafe("KPEX_PASSKEY_USERNAME"));
	}

	[Fact]
	public void Import_RejectsInvalidEditableFieldId()
	{
		string invalidId = Prefix + BasicAuth.Replace("dXNlcm5hbWU", "not-base64!") + Suffix;
		var database = NewDatabase();
		using (var input = JsonStream(invalidId))
			Assert.Throws<InvalidDataException>(() => new CxfFileFormatProvider().Import(database, input, new TestStatusLogger()));
	}

	[Fact]
	public void Import_DoesNotFallbackToAccountUsernameWhenBasicAuthUsernameIsMissing()
	{
		const string basicAuthWithoutUsername = "{\"type\":\"basic-auth\",\"password\":{\"fieldType\":\"concealed-string\",\"value\":\"login-password\"}}";
		var database = NewDatabase();
		using (var input = JsonStream(Prefix + basicAuthWithoutUsername + Suffix))
			new CxfFileFormatProvider().Import(database, input, new TestStatusLogger());

		var entry = database.RootGroup.GetEntries(true).GetAt(0);
		Assert.Equal(string.Empty, entry.Strings.ReadSafe(PwDefs.UserNameField));
		Assert.Equal("login-password", entry.Strings.ReadSafe(PwDefs.PasswordField));
	}

	[Fact]
	public void Import_ImportsAllBasicAuthCredentialsAndWarnsForAdditionalCredentials()
	{
		var database = NewDatabase();
		var logger = new TestStatusLogger();
		const string secondBasicAuth = "{\"type\":\"basic-auth\",\"username\":{\"fieldType\":\"string\",\"value\":\"second-user\"},\"password\":{\"fieldType\":\"concealed-string\",\"value\":\"second-password\"}}";
		using (var input = JsonStream(Prefix + BasicAuth + "," + secondBasicAuth + Suffix))
			new CxfFileFormatProvider().Import(database, input, logger);

		var entries = database.RootGroup.GetEntries(true);
		Assert.Equal((uint)2, entries.UCount);
		Assert.Equal("login-user", entries.GetAt(0).Strings.ReadSafe(PwDefs.UserNameField));
		Assert.Equal("login-password", entries.GetAt(0).Strings.ReadSafe(PwDefs.PasswordField));
		Assert.Equal("second-user", entries.GetAt(1).Strings.ReadSafe(PwDefs.UserNameField));
		Assert.Equal("second-password", entries.GetAt(1).Strings.ReadSafe(PwDefs.PasswordField));
		Assert.Single(logger.Warnings);
		Assert.Contains("multiple basic-auth credentials", logger.Warnings[0]);
		Assert.Contains("all will be imported", logger.Warnings[0]);
	}

	[Fact]
	public void Import_CombinesFirstBasicAuthAndPasskeyAndImportsAdditionalCredentialsSeparately()
	{
		var database = NewDatabase();
		var logger = new TestStatusLogger();
		const string secondPasskey = "{\"type\":\"passkey\",\"credentialId\":\"c2Vjb25kLWNyZWRlbnRpYWw\",\"rpId\":\"example.com\",\"username\":\"second-passkey-user\",\"userDisplayName\":\"Second Display Name\",\"userHandle\":\"dXNlci1oYW5kbGU\",\"key\":\"" + PrivateKey + "\"}";
		const string secondBasicAuth = "{\"type\":\"basic-auth\",\"username\":{\"fieldType\":\"string\",\"value\":\"second-user\"},\"password\":{\"fieldType\":\"concealed-string\",\"value\":\"second-password\"}}";
		using (var input = JsonStream(Prefix + BasicAuth + "," + secondBasicAuth + "," + Passkey + "," + secondPasskey + Suffix))
			new CxfFileFormatProvider().Import(database, input, logger);

		var entries = database.RootGroup.GetEntries(true);
		Assert.Equal((uint)3, entries.UCount);
		Assert.Equal("login-user", entries.GetAt(0).Strings.ReadSafe(PwDefs.UserNameField));
		Assert.Equal("login-password", entries.GetAt(0).Strings.ReadSafe(PwDefs.PasswordField));
		Assert.True(entries.GetAt(0).Strings.GetSafe(PwDefs.PasswordField).IsProtected);
		Assert.Equal("Y3JlZGVudGlhbElk", entries.GetAt(0).Strings.ReadSafe("KPEX_PASSKEY_CREDENTIAL_ID"));
		Assert.Equal("second-user", entries.GetAt(1).Strings.ReadSafe(PwDefs.UserNameField));
		Assert.Equal("second-password", entries.GetAt(1).Strings.ReadSafe(PwDefs.PasswordField));
		Assert.Equal(string.Empty, entries.GetAt(1).Strings.ReadSafe("KPEX_PASSKEY_CREDENTIAL_ID"));
		Assert.Equal(string.Empty, entries.GetAt(2).Strings.ReadSafe(PwDefs.UserNameField));
		Assert.Equal("c2Vjb25kLWNyZWRlbnRpYWw", entries.GetAt(2).Strings.ReadSafe("KPEX_PASSKEY_CREDENTIAL_ID"));
		Assert.Equal("second-passkey-user", entries.GetAt(2).Strings.ReadSafe("KPEX_PASSKEY_USERNAME"));
		Assert.Equal(2, logger.Warnings.Count);
		Assert.Contains("multiple passkey credentials", logger.Warnings[0]);
		Assert.Contains("separate entry", logger.Warnings[0]);
		Assert.Contains("multiple basic-auth credentials", logger.Warnings[1]);
		Assert.Contains("all will be imported", logger.Warnings[1]);
	}

	[Fact]
	public void Import_BasicAuthOnlyCreatesKeePassEntry()
	{
		var database = NewDatabase();
		using (var input = JsonStream(Prefix + BasicAuth + Suffix))
			new CxfFileFormatProvider().Import(database, input, new TestStatusLogger());

		var entries = database.RootGroup.GetEntries(true);
		Assert.Equal((uint)1, entries.UCount);
		var entry = entries.GetAt(0);
		Assert.Equal("Example passkey", entry.Strings.ReadSafe(PwDefs.TitleField));
		Assert.Equal("login-user", entry.Strings.ReadSafe(PwDefs.UserNameField));
		Assert.Equal("login-password", entry.Strings.ReadSafe(PwDefs.PasswordField));
		Assert.True(entry.Strings.GetSafe(PwDefs.PasswordField).IsProtected);
	}

	[Fact]
	public void Import_MapsSubtitleAndFirstScopeUrlAndWarnsForMultipleUrls()
	{
		var database = NewDatabase();
		var logger = new TestStatusLogger();
		string document = (Prefix + Passkey + Suffix).Replace(
			"\"title\":\"Example passkey\",",
			"\"title\":\"Example passkey\",\"subtitle\":\"Imported notes\",\"scope\":{\"urls\":[\"https://first.example/login\",\"https://second.example/login\"],\"androidApps\":[]},\"tags\":[\"work\",\"security\"],");
		using (var input = JsonStream(document))
			new CxfFileFormatProvider().Import(database, input, logger);

		var entry = database.RootGroup.GetEntries(true).GetAt(0);
		Assert.Equal("Imported notes", entry.Strings.ReadSafe(PwDefs.NotesField));
		Assert.Equal("https://first.example/login", entry.Strings.ReadSafe(PwDefs.UrlField));
		Assert.Equal(new[] { "security", "work" }, entry.Tags);
		Assert.Single(logger.Warnings);
		Assert.Contains("multiple scope URLs", logger.Warnings[0]);
		Assert.Contains("first URL", logger.Warnings[0]);
	}

	[Fact]
	public void Import_CreatesNestedGroupsAndPlacesEntriesUsingCollectionLinks()
	{
		var database = NewDatabase();
		var logger = new TestStatusLogger();
		string nestedId = "ICEiIyQlJicoKSorLC0uLw";
		string collections = "{\"id\":\"" + CollectionId + "\",\"title\":\"Imported folder\",\"subtitle\":\"Folder notes\",\"items\":[],\"subCollections\":[{\"id\":\"" + nestedId + "\",\"title\":\"Nested folder\",\"items\":[{\"item\":\"" + ItemId + "\"}]}]}";
		using (var input = JsonStream(DocumentWithCollections(collections)))
			new CxfFileFormatProvider().Import(database, input, logger);

		var folder = database.RootGroup.Groups.GetAt(0);
		var nestedFolder = folder.Groups.GetAt(0);
		var entry = database.RootGroup.GetEntries(true).GetAt(0);
		Assert.Equal(new byte[] { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F }, folder.Uuid.UuidBytes);
		Assert.Equal("Imported folder", folder.Name);
		Assert.Equal("Folder notes", folder.Notes);
		Assert.Equal("Nested folder", nestedFolder.Name);
		Assert.Equal(new byte[] { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F }, nestedFolder.Uuid.UuidBytes);
		Assert.Same(nestedFolder, entry.ParentGroup);
		Assert.Empty(logger.Warnings);
	}

	[Fact]
	public void Import_InvalidCollectionUuidCreatesGroupWithImportedPropertiesWithoutWarning()
	{
		var database = NewDatabase();
		var logger = new TestStatusLogger();
		string collection = "{\"id\":\"collection not uuid\",\"creationAt\":1705142400,\"modifiedAt\":1705228800,\"title\":\"Imported folder\",\"subtitle\":\"Folder notes\",\"items\":[{\"item\":\"" + ItemId + "\"}]}";
		using (var input = JsonStream(DocumentWithCollections(collection)))
			new CxfFileFormatProvider().Import(database, input, logger);

		var importedGroup = database.RootGroup.Groups.GetAt(0);
		var entry = importedGroup.Entries.GetAt(0);
		Assert.NotEqual(PwUuid.Zero, importedGroup.Uuid);
		Assert.Equal("Imported folder", importedGroup.Name);
		Assert.Equal("Folder notes", importedGroup.Notes);
		Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1705142400).UtcDateTime, importedGroup.CreationTime);
		Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1705228800).UtcDateTime, importedGroup.LastModificationTime);
		Assert.Same(importedGroup, entry.ParentGroup);
		Assert.Empty(logger.Warnings);
	}

	[Fact]
	public void Import_ReusesExistingGroupWithoutChangingItAndLogsWarning()
	{
		var database = NewDatabase();
		var existingGroup = new PwGroup(true, true) { Name = "Keep this name", Notes = "Keep these notes" };
		existingGroup.Uuid = new PwUuid(Convert.FromBase64String("EBESExQVFhcYGRobHB0eHw=="));
		database.RootGroup.AddGroup(existingGroup, true);
		var logger = new TestStatusLogger();
		string collection = "{\"id\":\"" + CollectionId + "\",\"title\":\"Incoming name\",\"subtitle\":\"Incoming notes\",\"items\":[{\"item\":\"" + ItemId + "\"}]}";
		using (var input = JsonStream(DocumentWithCollections(collection)))
			new CxfFileFormatProvider().Import(database, input, logger);

		var importedEntry = existingGroup.Entries.GetAt(0);
		Assert.Same(existingGroup, importedEntry.ParentGroup);
		Assert.Equal("Keep this name", existingGroup.Name);
		Assert.Equal("Keep these notes", existingGroup.Notes);
		Assert.Single(logger.Warnings);
		Assert.Contains(CollectionId, logger.Warnings[0]);
	}

	[Fact]
	public void Import_RejectsAccountWithMissingOrInvalidRequiredFields()
	{
		string account = "\"id\":\"YWNjb3VudA\",\"username\":\"account-user\",\"email\":\"user@example.com\",\"collections\":[],\"items\":[]";
		string[] invalidAccounts =
		{
			account.Replace("\"id\":\"YWNjb3VudA\",", string.Empty),
			account.Replace("\"id\":\"YWNjb3VudA\"", "\"id\":\"\""),
			account.Replace("\"username\":\"account-user\",", string.Empty),
			account.Replace("\"username\":\"account-user\"", "\"username\":null"),
			account.Replace("\"email\":\"user@example.com\",", string.Empty),
			account.Replace("\"email\":\"user@example.com\"", "\"email\":null"),
			account.Replace("\"collections\":[],", string.Empty),
			account.Replace("\"collections\":[]", "\"collections\":null"),
			account.Replace("\"collections\":[]", "\"collections\":{}"),
			account.Replace("\"items\":[]", string.Empty),
			account.Replace("\"items\":[]", "\"items\":null"),
			account.Replace("\"items\":[]", "\"items\":{}"),
		};

		foreach (string invalidAccount in invalidAccounts)
		{
			var database = NewDatabase();
			using (var input = JsonStream(AccountDocument(invalidAccount)))
			{
				Assert.Throws<InvalidDataException>(() => new CxfFileFormatProvider().Import(database, input, new TestStatusLogger()));
				Assert.Equal((uint)0, database.RootGroup.GetEntries(true).UCount);
			}
		}
	}


	[Fact]
	public void Import_RejectsMissingOrEmptyItemId()
	{
		string itemId = "\"id\":\"" + ItemId + "\",";
		string[] invalidDocuments =
		{
			(Prefix + Passkey + Suffix).Replace(itemId, string.Empty),
			(Prefix + Passkey + Suffix).Replace(itemId, "\"id\":\"\","),
		};

		foreach (string document in invalidDocuments)
		{
			var database = NewDatabase();
			using (var input = JsonStream(document))
			{
				Assert.Throws<InvalidDataException>(() => new CxfFileFormatProvider().Import(database, input, new TestStatusLogger()));
				Assert.Equal((uint)0, database.RootGroup.GetEntries(true).UCount);
			}
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
		Assert.False(provider.ImportAppendsToRootGroupOnly);
	}

	private static string AccountDocument(string account) =>
		"{\"version\":{\"major\":1,\"minor\":0},\"exporterRpId\":\"exporter.example.com\",\"exporterDisplayName\":\"Exporter\",\"timestamp\":1705228800,\"accounts\":[{" + account + "}]}";

	private static string DocumentWithCollections(string collections) =>
		(Prefix + Passkey + Suffix).Replace("\"collections\":[]", "\"collections\":[" + collections + "]");

	private static PwDatabase NewDatabase()
	{
		var database = new PwDatabase();
		database.New(IOConnectionInfo.FromPath("cxf-import-test.kdbx"), new CompositeKey());
		return database;
	}

	private static MemoryStream JsonStream(string json) => new(Encoding.UTF8.GetBytes(json));

	private sealed class TestStatusLogger : IStatusLogger
	{
		internal List<string> Warnings { get; } = new List<string>();

		public void StartLogging(string strOperation, bool bWriteOperationToLog) { }
		public void EndLogging() { }
		public bool SetProgress(uint uPercent) => true;
		public bool SetText(string strText, LogStatusType lsType)
		{
			if (lsType == LogStatusType.Warning) Warnings.Add(strText);
			return true;
		}
		public bool ContinueWork() => true;
	}
}
