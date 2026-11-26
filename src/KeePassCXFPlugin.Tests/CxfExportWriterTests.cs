// SPDX-FileCopyrightText: Copyright (C) 2026 Michael Hüpkes
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using KeePass.DataExchange;
using KeePassCXF;
using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;
using Xunit;

namespace KeePassCXFPlugin.Tests;

public class CxfExportWriterTests
{
	private const string FieldCredentialId = "KPEX_PASSKEY_CREDENTIAL_ID";
	private const string FieldPrivateKey = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
	private const string FieldRelyingParty = "KPEX_PASSKEY_RELYING_PARTY";
	private const string FieldUserHandle = "KPEX_PASSKEY_USER_HANDLE";
	private const string FieldUsername = "KPEX_PASSKEY_USERNAME";

	[Fact]
	public void Export_WritesPasskeyAsCxfJsonAndUsesPkcs8DerBase64Url()
	{
		byte[] der = { 0x30, 0x03, 0x02, 0x01, 0x01 };
		var database = NewDatabase();
		var entry = NewPasskeyEntry(der);
		entry.Strings.Set(PwDefs.NotesField, new ProtectedString(false, "Passkey notes"));
		entry.Strings.Set(PwDefs.UrlField, new ProtectedString(false, "https://example.com/login"));
		entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "standard-password"));
		entry.AddTag("work");
		entry.AddTag("security");
		var secondEntry = NewPasskeyEntry(der);
		secondEntry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, "Second passkey"));
		secondEntry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, string.Empty));
		database.RootGroup.AddEntry(entry, true);
		database.RootGroup.AddEntry(secondEntry, true);
		using var output = new MemoryStream();

		bool exported = CxfExportWriter.Export(new PwExportInfo(database.RootGroup, database), output, new TestStatusLogger());

		Assert.True(exported);
		var json = Encoding.UTF8.GetString(output.ToArray());
		Assert.Contains("\n", json);
		Assert.Contains("\n  \"version\"", json);
		string compactJson = Regex.Replace(json, @"\s+", string.Empty);
		Assert.Contains("\"major\":1", compactJson);
		Assert.Contains("\"minor\":0", compactJson);
		Assert.Contains("\"exporterDisplayName\":\"KeePassCXF\"", compactJson);
		Assert.Contains("\"id\":\"" + EncodeBase64Url(database.RootGroup.Uuid.UuidBytes) + "\",\"username\":\"cxf-import-test.kdbx\"", compactJson);
		Assert.Contains("\"id\":\"" + EncodeBase64Url(entry.Uuid.UuidBytes) + "\"", compactJson);
		Assert.Contains("\"subtitle\": \"Passkey notes\"", json);
		Assert.Contains("\"scope\":{\"urls\":[\"https:\\/\\/example.com\\/login\"],\"androidApps\":[]}", compactJson);
		Assert.Contains("\"tags\":[\"security\",\"work\"]", compactJson);
		Assert.Contains("\"type\":\"basic-auth\",\"username\":{\"fieldType\":\"string\",\"value\":\"account-user\"", compactJson);
		Assert.Contains("\"password\":{\"fieldType\":\"concealed-string\",\"value\":\"standard-password\"", compactJson);
		Assert.Contains("\"label\": \"" + KeePass.Resources.KPRes.UserName + "\"", json);
		Assert.Contains("\"label\": \"" + KeePass.Resources.KPRes.Password + "\"", json);
		Assert.Single(Regex.Matches(compactJson, "\\\"type\\\":\\\"basic-auth\\\"").Cast<Match>());
		Assert.Single(Regex.Matches(compactJson, "\\\"subtitle\\\":").Cast<Match>());
		Assert.Single(Regex.Matches(compactJson, "\\\"scope\\\":").Cast<Match>());
		Assert.Single(Regex.Matches(compactJson, "\\\"tags\\\":").Cast<Match>());
		Assert.Contains("\"id\":\"" + EncodeBase64Url(secondEntry.Uuid.UuidBytes) + "\"", compactJson);
		Assert.Single(Regex.Matches(compactJson, "\\\"accounts\\\":\\[\\{"));
		Assert.Equal(2, Regex.Matches(compactJson, "\\\"type\\\":\\\"passkey\\\"").Count);
		Assert.Contains("\"type\":\"passkey\"", compactJson);
		Assert.Contains("\"credentialId\":\"Y3JlZGVudGlhbElk\"", compactJson);
		Assert.Contains("\"rpId\":\"example.com\"", compactJson);
		Assert.Contains("\"username\":\"passkey-user\"", compactJson);
		Assert.Contains("\"userHandle\":\"dXNlci1oYW5kbGU\"", compactJson);
		Assert.Contains("\"key\":\"MAMCAQE\"", compactJson);
		Assert.Contains("\"collections\":[]", compactJson);
		Assert.DoesNotContain("-----BEGIN PRIVATE KEY-----", json);
	}

	[Fact]
	public void Export_MapsNestedKeePassGroupsToCollectionsAndLinkedItems()
	{
		var database = NewDatabase();
		var folder = new PwGroup(true, true) { Name = "Folder", Notes = "Folder notes" };
		var nestedFolder = new PwGroup(true, true) { Name = "Nested folder" };
		var folderEntry = NewPasskeyEntry(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 });
		var nestedEntry = NewPasskeyEntry(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 });
		database.RootGroup.AddGroup(folder, true);
		Assert.Equal("Folder notes", folder.Notes);
		folder.AddEntry(folderEntry, true);
		folder.AddGroup(nestedFolder, true);
		nestedFolder.AddEntry(nestedEntry, true);
		using var output = new MemoryStream();

		bool exported = CxfExportWriter.Export(new PwExportInfo(database.RootGroup, database), output, new TestStatusLogger());

		Assert.True(exported);
		string json = Encoding.UTF8.GetString(output.ToArray());
		string compactJson = Regex.Replace(json, @"\s+", string.Empty);
		string folderId = EncodeBase64Url(folder.Uuid.UuidBytes);
		string nestedFolderId = EncodeBase64Url(nestedFolder.Uuid.UuidBytes);
		string folderEntryId = EncodeBase64Url(folderEntry.Uuid.UuidBytes);
		string nestedEntryId = EncodeBase64Url(nestedEntry.Uuid.UuidBytes);
		Assert.Contains("\"id\":\"" + folderId + "\"", compactJson);
		Assert.Contains("\"title\":\"Folder\"", compactJson);
		Assert.Contains("\"subtitle\": \"Folder notes\"", json);
		Assert.Contains("\"items\":[{\"item\":\"" + folderEntryId + "\"}]", compactJson);
		Assert.Contains("\"id\":\"" + nestedFolderId + "\"", compactJson);
		Assert.Contains("\"title\": \"Nested folder\"", json);
		Assert.Contains("\"items\":[{\"item\":\"" + nestedEntryId + "\"}]", compactJson);
		Assert.Single(Regex.Matches(compactJson, "\\\"subtitle\\\":"));
		Assert.Single(Regex.Matches(compactJson, "\\\"subCollections\\\":"));
	}

	[Fact]
	public void Export_SkipsEntriesAndCollectionsUnderRecycleBinAndEntryTemplatesGroups()
	{
		var database = NewDatabase();
		var recycleBin = new PwGroup(true, true) { Name = "Recycle Bin" };
		var recycleBinChild = new PwGroup(true, true) { Name = "Recycle Bin child" };
		var templates = new PwGroup(true, true) { Name = "Entry templates" };
		var templatesChild = new PwGroup(true, true) { Name = "Templates child" };
		var includedGroup = new PwGroup(true, true) { Name = "Included" };
		var recycleBinEntry = NewPasskeyEntry(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 });
		var recycleBinChildEntry = NewPasskeyEntry(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 });
		var templatesEntry = NewPasskeyEntry(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 });
		var templatesChildEntry = NewPasskeyEntry(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 });
		var includedEntry = NewPasskeyEntry(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 });
		database.RootGroup.AddGroup(recycleBin, true);
		database.RootGroup.AddGroup(templates, true);
		database.RootGroup.AddGroup(includedGroup, true);
		recycleBin.AddEntry(recycleBinEntry, true);
		recycleBin.AddGroup(recycleBinChild, true);
		recycleBinChild.AddEntry(recycleBinChildEntry, true);
		templates.AddEntry(templatesEntry, true);
		templates.AddGroup(templatesChild, true);
		templatesChild.AddEntry(templatesChildEntry, true);
		includedGroup.AddEntry(includedEntry, true);
		database.RecycleBinUuid = recycleBin.Uuid;
		database.EntryTemplatesGroup = templates.Uuid;
		using var output = new MemoryStream();

		bool exported = CxfExportWriter.Export(new PwExportInfo(database.RootGroup, database), output, new TestStatusLogger());

		Assert.True(exported);
		string json = Encoding.UTF8.GetString(output.ToArray());
		string compactJson = Regex.Replace(json, @"\s+", string.Empty);
		Assert.Contains("\"id\":\"" + EncodeBase64Url(includedEntry.Uuid.UuidBytes) + "\"", compactJson);
		Assert.DoesNotContain("\"id\":\"" + EncodeBase64Url(recycleBinEntry.Uuid.UuidBytes) + "\"", compactJson);
		Assert.DoesNotContain("\"id\":\"" + EncodeBase64Url(recycleBinChildEntry.Uuid.UuidBytes) + "\"", compactJson);
		Assert.DoesNotContain("\"id\":\"" + EncodeBase64Url(templatesEntry.Uuid.UuidBytes) + "\"", compactJson);
		Assert.DoesNotContain("\"id\":\"" + EncodeBase64Url(templatesChildEntry.Uuid.UuidBytes) + "\"", compactJson);
		Assert.Contains("\"title\":\"Included\"", compactJson);
		Assert.DoesNotContain("\"title\":\"Recycle Bin\"", compactJson);
		Assert.DoesNotContain("\"title\":\"Recycle Bin child\"", compactJson);
		Assert.DoesNotContain("\"title\":\"Entry templates\"", compactJson);
		Assert.DoesNotContain("\"title\":\"Templates child\"", compactJson);
	}

	[Fact]
	public void Export_BasicAuthOnlyEntryDoesNotRequirePasskeyData()
	{
		var database = NewDatabase();
		var entry = new PwEntry(true, true);
		entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, "Basic login"));
		entry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, "basic-user"));
		entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "basic-password"));
		database.RootGroup.AddEntry(entry, true);
		using var output = new MemoryStream();

		bool exported = CxfExportWriter.Export(new PwExportInfo(database.RootGroup, database), output, new TestStatusLogger());

		Assert.True(exported);
		string compactJson = Regex.Replace(Encoding.UTF8.GetString(output.ToArray()), @"\s+", string.Empty);
		Assert.Contains("\"id\":\"" + EncodeBase64Url(entry.Uuid.UuidBytes) + "\"", compactJson);
		Assert.Contains("\"type\":\"basic-auth\",\"username\":{\"fieldType\":\"string\",\"value\":\"basic-user\"", compactJson);
		Assert.Contains("\"password\":{\"fieldType\":\"concealed-string\",\"value\":\"basic-password\"", compactJson);
		string json = Encoding.UTF8.GetString(output.ToArray());
		Assert.Contains("\"label\": \"" + KeePass.Resources.KPRes.UserName + "\"", json);
		Assert.Contains("\"label\": \"" + KeePass.Resources.KPRes.Password + "\"", json);
		Assert.DoesNotContain("\"type\":\"passkey\"", compactJson);
	}

	[Fact]
	public void Export_SkipsEntriesWithoutPasskeysOrBasicAuth()
	{
		var database = NewDatabase();
		database.RootGroup.AddEntry(new PwEntry(true, true), true);
		using var output = new MemoryStream();

		bool exported = CxfExportWriter.Export(new PwExportInfo(database.RootGroup, database), output, new TestStatusLogger());

		Assert.True(exported);
		var json = Encoding.UTF8.GetString(output.ToArray());
		Assert.Contains("\"accounts\":[{", Regex.Replace(json, @"\s+", string.Empty));
		Assert.Contains("\"items\":[]", Regex.Replace(json, @"\s+", string.Empty));
	}

	[Fact]
	public void Export_WithMalformedPrivateKeyReturnsFalseWithoutWritingPayload()
	{
		var entry = NewPasskeyEntry(new byte[] { 0x30 });
		entry.Strings.Set(FieldPrivateKey, new ProtectedString(true, "not a PEM key"));
		var database = NewDatabase();
		database.RootGroup.AddEntry(entry, true);
		using var output = new MemoryStream();

		bool exported = CxfExportWriter.Export(new PwExportInfo(database.RootGroup, database), output, new TestStatusLogger());

		Assert.False(exported);
		Assert.Equal(0, output.Length);
	}

	private static PwDatabase NewDatabase()
	{
		var database = new PwDatabase();
		database.New(IOConnectionInfo.FromPath("cxf-import-test.kdbx"), new CompositeKey());
		return database;
	}

	private static string EncodeBase64Url(byte[] value) =>
		Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

	private static PwEntry NewPasskeyEntry(byte[] der)
	{
		string encodedKey = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
		var entry = new PwEntry(true, true);
		entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, "Example passkey"));
		entry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, "account-user"));
		entry.Strings.Set(FieldCredentialId, new ProtectedString(true, "Y3JlZGVudGlhbElk"));
		entry.Strings.Set(FieldPrivateKey, new ProtectedString(true,
			"-----BEGIN PRIVATE KEY-----\r\n" + encodedKey + "\r\n-----END PRIVATE KEY-----\r\n"));
		entry.Strings.Set(FieldRelyingParty, new ProtectedString(false, "example.com"));
		entry.Strings.Set(FieldUserHandle, new ProtectedString(true, "dXNlci1oYW5kbGU"));
		entry.Strings.Set(FieldUsername, new ProtectedString(false, "passkey-user"));
		return entry;
	}

	private sealed class TestStatusLogger : IStatusLogger
	{
		public void StartLogging(string strOperation, bool bWriteOperationToLog) { }
		public void EndLogging() { }
		public bool SetProgress(uint uPercent) => true;
		public bool SetText(string strText, LogStatusType lsType) => true;
		public bool ContinueWork() => true;
	}
}
