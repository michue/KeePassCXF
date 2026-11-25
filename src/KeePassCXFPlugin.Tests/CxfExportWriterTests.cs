// SPDX-FileCopyrightText: Copyright (C) 2026 Michael Hüpkes
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using System.Text;
using KeePass.DataExchange;
using KeePassCXF;
using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Security;
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
		var entry = NewPasskeyEntry(der);
		var group = new PwGroup(true, true) { Name = "Root" };
		group.AddEntry(entry, true);
		using var output = new MemoryStream();

		bool exported = CxfExportWriter.Export(new PwExportInfo(group, null), output, new TestStatusLogger());

		Assert.True(exported);
		var json = Encoding.UTF8.GetString(output.ToArray());
		Assert.Contains("\"major\":1", json);
		Assert.Contains("\"minor\":0", json);
		Assert.Contains("\"exporterDisplayName\":\"KeePassCXF\"", json);
		Assert.Contains("\"type\":\"passkey\"", json);
		Assert.Contains("\"credentialId\":\"credential-id\"", json);
		Assert.Contains("\"rpId\":\"example.com\"", json);
		Assert.Contains("\"username\":\"passkey-user\"", json);
		Assert.Contains("\"userHandle\":\"user-handle\"", json);
		Assert.Contains("\"key\":\"MAMCAQE\"", json);
		Assert.Contains("\"collections\":[]", json);
		Assert.DoesNotContain("-----BEGIN PRIVATE KEY-----", json);
	}

	[Fact]
	public void Export_SkipsEntriesWithoutPasskeys()
	{
		var group = new PwGroup(true, true);
		group.AddEntry(new PwEntry(true, true), true);
		using var output = new MemoryStream();

		bool exported = CxfExportWriter.Export(new PwExportInfo(group, null), output, new TestStatusLogger());

		Assert.True(exported);
		var json = Encoding.UTF8.GetString(output.ToArray());
		Assert.Contains("\"accounts\":[]", json);
	}

	[Fact]
	public void Export_WithMalformedPrivateKeyReturnsFalseWithoutWritingPayload()
	{
		var entry = NewPasskeyEntry(new byte[] { 0x30 });
		entry.Strings.Set(FieldPrivateKey, new ProtectedString(true, "not a PEM key"));
		var group = new PwGroup(true, true);
		group.AddEntry(entry, true);
		using var output = new MemoryStream();

		bool exported = CxfExportWriter.Export(new PwExportInfo(group, null), output, new TestStatusLogger());

		Assert.False(exported);
		Assert.Equal(0, output.Length);
	}

	private static PwEntry NewPasskeyEntry(byte[] der)
	{
		string encodedKey = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
		var entry = new PwEntry(true, true);
		entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, "Example passkey"));
		entry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, "account-user"));
		entry.Strings.Set(FieldCredentialId, new ProtectedString(true, "credential-id"));
		entry.Strings.Set(FieldPrivateKey, new ProtectedString(true,
			"-----BEGIN PRIVATE KEY-----\r\n" + encodedKey + "\r\n-----END PRIVATE KEY-----\r\n"));
		entry.Strings.Set(FieldRelyingParty, new ProtectedString(false, "example.com"));
		entry.Strings.Set(FieldUserHandle, new ProtectedString(true, "user-handle"));
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
