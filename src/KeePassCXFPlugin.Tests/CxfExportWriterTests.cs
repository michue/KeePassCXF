// SPDX-FileCopyrightText: Copyright (C) 2026 Michael Hüpkes
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
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
		var secondEntry = NewPasskeyEntry(der);
		secondEntry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, "Second passkey"));
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
		Assert.Contains("\"id\":\"" + EncodeBase64Url(secondEntry.Uuid.UuidBytes) + "\"", compactJson);
		Assert.Equal(1, Regex.Matches(compactJson, "\\\"accounts\\\":\\[\\{").Count);
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
	public void Export_SkipsEntriesWithoutPasskeys()
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
