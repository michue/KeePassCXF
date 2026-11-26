// SPDX-FileCopyrightText: Copyright (C) 2026 Michael Hüpkes
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Web.Script.Serialization;
using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Security;
using KeePassLib.Utility;

namespace KeePassCXF;

internal static class CxfImportReader
{
	private const string FieldCredentialId = "KPEX_PASSKEY_CREDENTIAL_ID";
	private const string FieldPrivateKey = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
	private const string FieldRelyingParty = "KPEX_PASSKEY_RELYING_PARTY";
	private const string FieldUserHandle = "KPEX_PASSKEY_USER_HANDLE";
	private const string FieldUsername = "KPEX_PASSKEY_USERNAME";

	internal static void Import(PwDatabase database, Stream input, IStatusLogger statusLogger)
	{
		CxfExportWriter.CxfHeader document;
		try
		{
			var serializer = new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 100 };
			using (var reader = new StreamReader(input, Encoding.UTF8, true, 4096, true))
			{
				var root = AsObject(serializer.DeserializeObject(reader.ReadToEnd()), "CXF document");
				document = ParseDocument(root);
			}
			ValidateHeader(document);
		}
		catch (SerializationException ex)
		{
			throw ReportInvalidDocument(statusLogger, ex);
		}
		catch (InvalidOperationException ex)
		{
			throw ReportInvalidDocument(statusLogger, ex);
		}
		catch (ArgumentException ex)
		{
			throw ReportInvalidDocument(statusLogger, ex);
		}

		var importedEntries = new List<PwEntry>();
		int credentialsRead = 0;
		try
		{
			foreach (var account in document.Accounts)
			{
				if (account?.Items == null) continue;
				string accountUsername = !string.IsNullOrEmpty(account.Username) ? account.Username : account.Email ?? string.Empty;

				foreach (var item in account.Items)
				{
					if (item?.Credentials == null) continue;
					foreach (var credential in item.Credentials)
					{
						if (!statusLogger.ContinueWork()) return;
						if (credential == null || !string.Equals(credential.Type, "passkey", StringComparison.Ordinal)) continue;

						statusLogger.SetText($"Validating passkey '{item.Title ?? string.Empty}'...", LogStatusType.Info);
						importedEntries.Add(CreateEntry(accountUsername, item, credential));
						credentialsRead++;
					}
				}
			}
		}
		catch (InvalidDataException ex)
		{
			throw ReportInvalidDocument(statusLogger, ex);
		}
		catch (FormatException ex)
		{
			throw ReportInvalidDocument(statusLogger, ex);
		}
		catch (ArgumentOutOfRangeException ex)
		{
			throw ReportInvalidDocument(statusLogger, ex);
		}

		if (!database.IsOpen)
			throw new InvalidOperationException("Cannot import CXF entries into a closed KeePass database.");

		if (!statusLogger.ContinueWork()) return;

		statusLogger.SetText($"Importing {credentialsRead} passkey(s)...", LogStatusType.Info);
		foreach (var entry in importedEntries)
			database.RootGroup.AddEntry(entry, true);
		statusLogger.SetText($"Imported {credentialsRead} passkey(s).", LogStatusType.Info);
	}

	private static CxfExportWriter.CxfHeader ParseDocument(Dictionary<string, object> root)
	{
		var version = AsObject(GetValue(root, "version"), "version");
		var accounts = AsArray(GetValue(root, "accounts"), "accounts");
		var parsedAccounts = new List<CxfExportWriter.CxfAccount>();
		foreach (var value in accounts)
		{
			var account = AsObject(value, "account");
			var itemsValue = GetValue(account, "items");
			var items = itemsValue == null ? Array.Empty<object>() : AsArray(itemsValue, "items");
			var parsedItems = new List<CxfExportWriter.CxfItem>();
			foreach (var itemValue in items)
			{
				var item = AsObject(itemValue, "item");
				var credentialValues = GetValue(item, "credentials");
				var credentialArray = credentialValues == null ? Array.Empty<object>() : AsArray(credentialValues, "credentials");
				var credentials = new List<CxfExportWriter.CxfPasskey>();
				foreach (var credentialValue in credentialArray)
				{
					var credential = AsObject(credentialValue, "credential");
					var type = GetString(credential, "type");
					if (!string.Equals(type, "passkey", StringComparison.Ordinal))
					{
						credentials.Add(new CxfExportWriter.CxfPasskey { Type = type });
						continue;
					}

					credentials.Add(new CxfExportWriter.CxfPasskey
					{
						Type = type,
						CredentialId = GetString(credential, "credentialId"),
						RpId = GetString(credential, "rpId"),
						Username = GetString(credential, "username"),
						UserDisplayName = GetString(credential, "userDisplayName"),
						UserHandle = GetString(credential, "userHandle"),
						Key = GetString(credential, "key"),
					});
				}

				parsedItems.Add(new CxfExportWriter.CxfItem
				{
					Id = GetString(item, "id"),
					CreationAt = GetNullableInt64(item, "creationAt"),
					ModifiedAt = GetNullableInt64(item, "modifiedAt"),
					Title = GetString(item, "title"),
					Credentials = credentials.ToArray(),
				});
			}

			parsedAccounts.Add(new CxfExportWriter.CxfAccount
			{
				Id = GetString(account, "id"),
				Username = GetString(account, "username"),
				Email = GetString(account, "email"),
				Items = parsedItems.ToArray(),
			});
		}

		return new CxfExportWriter.CxfHeader
		{
			Version = new CxfExportWriter.CxfVersion
			{
				Major = GetInt32(version, "major"),
				Minor = GetInt32(version, "minor"),
			},
			ExporterRpId = GetString(root, "exporterRpId"),
			ExporterDisplayName = GetString(root, "exporterDisplayName"),
			Timestamp = GetInt64(root, "timestamp"),
			Accounts = parsedAccounts.ToArray(),
		};
	}

	private static Dictionary<string, object> AsObject(object value, string name) =>
		value as Dictionary<string, object>
		?? throw new SerializationException($"The CXF {name} must be a JSON object.");

	private static object[] AsArray(object value, string name) =>
		value as object[]
		?? throw new SerializationException($"The CXF {name} must be a JSON array.");

	private static object GetValue(Dictionary<string, object> value, string name) =>
		value.TryGetValue(name, out var result) ? result : null;

	private static string GetString(Dictionary<string, object> value, string name)
	{
		object result = GetValue(value, name);
		if (result == null) return null;
		if (result is string text) return text;
		throw new SerializationException($"The CXF field '{name}' must be a string.");
	}

	private static int GetInt32(Dictionary<string, object> value, string name)
	{
		long result = GetInt64(value, name);
		if (result < int.MinValue || result > int.MaxValue)
			throw new SerializationException($"The CXF field '{name}' is out of range.");
		return (int)result;
	}

	private static long GetInt64(Dictionary<string, object> value, string name)
	{
		object result = GetValue(value, name);
		if (result is int int32) return int32;
		if (result is long int64) return int64;
		if (result is decimal decimalValue && decimal.Truncate(decimalValue) == decimalValue
			&& decimalValue >= long.MinValue && decimalValue <= long.MaxValue)
			return (long)decimalValue;
		throw new SerializationException($"The CXF field '{name}' must be an integer.");
	}

	private static long? GetNullableInt64(Dictionary<string, object> value, string name)
	{
		return GetValue(value, name) == null ? (long?)null : GetInt64(value, name);
	}

	private static void ValidateHeader(CxfExportWriter.CxfHeader document)
	{
		if (document?.Version == null)
			throw new SerializationException("The CXF document has no version information.");
		if (document.Version.Major != 1)
			throw new SerializationException($"CXF major version {document.Version.Major} is not supported.");
		if (string.IsNullOrWhiteSpace(document.ExporterRpId)
			|| string.IsNullOrWhiteSpace(document.ExporterDisplayName)
			|| document.Timestamp <= 0)
			throw new SerializationException("The CXF document is missing required exporter metadata.");
		if (document.Accounts == null)
			throw new SerializationException("The CXF document has no accounts array.");
	}

	private static PwEntry CreateEntry(string accountUsername, CxfExportWriter.CxfItem item,
		CxfExportWriter.CxfPasskey credential)
	{
		if (string.IsNullOrWhiteSpace(item.Id))
			throw new InvalidDataException("A CXF passkey item has no ID.");
		if (item.Title == null)
			throw new InvalidDataException("A CXF passkey item has no title.");
		if (string.IsNullOrWhiteSpace(credential.CredentialId))
			throw new InvalidDataException("A CXF passkey has no credential ID.");
		if (string.IsNullOrWhiteSpace(credential.RpId))
			throw new InvalidDataException("A CXF passkey has no relying party ID.");
		if (credential.Username == null || credential.UserDisplayName == null
			|| credential.UserHandle == null || string.IsNullOrEmpty(credential.Key))
			throw new InvalidDataException("A CXF passkey is missing required fields.");

		ValidateBase64Url(credential.CredentialId, "credential ID");
		ValidateBase64Url(credential.UserHandle, "user handle");
		byte[] privateKey = DecodeBase64Url(credential.Key, "private key");
		try
		{
			ValidatePkcs8PrivateKey(privateKey);
			var entry = new PwEntry(true, true);
			if (TryGetItemUuid(item.Id, out var itemUuid))
				entry.Uuid = itemUuid;
			entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, item.Title ?? string.Empty));
			entry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, accountUsername));
			entry.Strings.Set(PwDefs.PasswordField, ProtectedString.EmptyEx);
			entry.Strings.Set(FieldCredentialId, new ProtectedString(true, credential.CredentialId));
			entry.Strings.Set(FieldPrivateKey, new ProtectedString(true, EncodePkcs8Pem(privateKey)));
			entry.Strings.Set(FieldRelyingParty, new ProtectedString(false, credential.RpId));
			entry.Strings.Set(FieldUserHandle, new ProtectedString(true, credential.UserHandle));
			entry.Strings.Set(FieldUsername, new ProtectedString(false, credential.Username));
			entry.IconId = PwIcon.MultiKeys;

			if (item.CreationAt.HasValue)
			{
				if (item.CreationAt.Value < 0) throw new InvalidDataException("The CXF item creation time is invalid.");
				entry.CreationTime = DateTimeOffset.FromUnixTimeSeconds(item.CreationAt.Value).UtcDateTime;
			}
			if (item.ModifiedAt.HasValue)
			{
				if (item.ModifiedAt.Value < 0) throw new InvalidDataException("The CXF item modification time is invalid.");
				entry.LastModificationTime = DateTimeOffset.FromUnixTimeSeconds(item.ModifiedAt.Value).UtcDateTime;
			}
			return entry;
		}
		finally
		{
			MemUtil.ZeroByteArray(privateKey);
		}
	}

	private static bool TryGetItemUuid(string value, out PwUuid uuid)
	{
		uuid = null;
		if (string.IsNullOrEmpty(value)) return false;

		byte[] bytes = null;
		try
		{
			bytes = DecodeBase64Url(value, "item ID");
			if (bytes.Length != 16) return false;
			var parsedUuid = new PwUuid(bytes);
			if (parsedUuid.IsZero) return false;
			uuid = parsedUuid;
			return true;
		}
		catch (InvalidDataException)
		{
			return false;
		}
		finally
		{
			if (bytes != null) MemUtil.ZeroByteArray(bytes);
		}
	}

	private static void ValidateBase64Url(string value, string description)
	{
		byte[] decoded = DecodeBase64Url(value, description);
		MemUtil.ZeroByteArray(decoded);
	}

	private static byte[] DecodeBase64Url(string value, string description)
	{
		if (string.IsNullOrEmpty(value))
			throw new InvalidDataException($"The CXF passkey {description} is empty.");

		int paddingStart = value.IndexOf('=');
		int dataLength = paddingStart < 0 ? value.Length : paddingStart;
		int paddingLength = value.Length - dataLength;
		if (paddingLength > 2)
			throw new InvalidDataException($"The CXF passkey {description} is not valid base64url.");
		if (paddingStart >= 0)
			for (int i = paddingStart; i < value.Length; i++)
				if (value[i] != '=')
					throw new InvalidDataException($"The CXF passkey {description} is not valid base64url.");
		for (int i = 0; i < dataLength; i++)
		{
			char c = value[i];
			if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'))
				throw new InvalidDataException($"The CXF passkey {description} is not valid base64url.");
		}
		if (dataLength % 4 == 1 || (paddingLength != 0 && value.Length % 4 != 0))
			throw new InvalidDataException($"The CXF passkey {description} is not valid base64url.");

		string base64 = value.Substring(0, dataLength).Replace('-', '+').Replace('_', '/')
			+ new string('=', (4 - dataLength % 4) % 4);
		try
		{
			return Convert.FromBase64String(base64);
		}
		catch (FormatException ex)
		{
			throw new InvalidDataException($"The CXF passkey {description} is not valid base64url.", ex);
		}
	}

	private static void ValidatePkcs8PrivateKey(byte[] data)
	{
		int offset = 0;
		if (ReadDerElement(data, ref offset, 0x30) != data.Length)
			throw new InvalidDataException("The CXF passkey key is not a valid PKCS#8 private key.");

		int outerEnd = data.Length;
		int versionEnd = ReadDerElement(data, ref offset, 0x02);
		if (versionEnd - offset != 1 || (data[offset] != 0 && data[offset] != 1))
			throw new InvalidDataException("The CXF passkey key has an invalid PKCS#8 version.");
		offset = versionEnd;

		int algorithmEnd = ReadDerElement(data, ref offset, 0x30);
		int oidEnd = ReadDerElement(data, ref offset, 0x06);
		if (oidEnd == offset || oidEnd > algorithmEnd)
			throw new InvalidDataException("The CXF passkey key has an invalid algorithm identifier.");
		offset = oidEnd;
		if (offset < algorithmEnd)
		{
			byte parameterTag = data[offset];
			if (parameterTag != 0x05 && parameterTag != 0x06 && parameterTag != 0x30)
				throw new InvalidDataException("The CXF passkey key has an invalid algorithm parameter.");
			offset = ReadDerElement(data, ref offset, parameterTag);
		}
		if (offset != algorithmEnd)
			throw new InvalidDataException("The CXF passkey key has an invalid algorithm identifier.");

		int privateKeyEnd = ReadDerElement(data, ref offset, 0x04);
		if (privateKeyEnd == offset)
			throw new InvalidDataException("The CXF passkey key is empty.");
		offset = privateKeyEnd;
		while (offset < outerEnd)
		{
			byte tag = data[offset];
			if (tag != 0xA0 && tag != 0x81)
				throw new InvalidDataException("The CXF passkey key has invalid PKCS#8 data.");
			offset = ReadDerElement(data, ref offset, tag);
		}
		if (offset != outerEnd)
			throw new InvalidDataException("The CXF passkey key has invalid PKCS#8 data.");
	}

	private static int ReadDerElement(byte[] data, ref int offset, byte expectedTag)
	{
		if (offset >= data.Length || data[offset++] != expectedTag || offset >= data.Length)
			throw new InvalidDataException("The CXF passkey key has invalid DER encoding.");

		int firstLength = data[offset++];
		int length;
		if ((firstLength & 0x80) == 0)
		{
			length = firstLength;
		}
		else
		{
			int lengthBytes = firstLength & 0x7f;
			if (lengthBytes == 0 || lengthBytes > 4 || offset + lengthBytes > data.Length || data[offset] == 0)
				throw new InvalidDataException("The CXF passkey key has invalid DER length encoding.");
			length = 0;
			for (int i = 0; i < lengthBytes; i++)
			{
				if (length > (int.MaxValue - data[offset]) / 256)
					throw new InvalidDataException("The CXF passkey key has an oversized DER length.");
				length = (length << 8) | data[offset++];
			}
			if (length < 128)
				throw new InvalidDataException("The CXF passkey key has non-canonical DER length encoding.");
		}
		if (length < 0 || length > data.Length - offset)
			throw new InvalidDataException("The CXF passkey key is truncated.");
		int end = offset + length;
		if (expectedTag != 0x30 && expectedTag != 0x02 && expectedTag != 0x04 && expectedTag != 0x06 && expectedTag != 0xA0 && expectedTag != 0x81 && expectedTag != 0x05)
			throw new InvalidDataException("The CXF passkey key contains unsupported DER data.");
		return end;
	}

	private static string EncodePkcs8Pem(byte[] der)
	{
		string base64 = Convert.ToBase64String(der);
		var pem = new StringBuilder("-----BEGIN PRIVATE KEY-----\r\n");
		for (int i = 0; i < base64.Length; i += 64)
			pem.Append(base64, i, Math.Min(64, base64.Length - i)).Append("\r\n");
		pem.Append("-----END PRIVATE KEY-----\r\n");
		return pem.ToString();
	}

	private static InvalidDataException ReportInvalidDocument(IStatusLogger statusLogger, Exception exception)
	{
		const string message = "The CXF file is malformed or contains an unsupported passkey.";
		statusLogger.SetText(message, LogStatusType.Error);
		return new InvalidDataException(message, exception);
	}
}
