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

		var importedEntries = new List<ImportedEntry>();
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
					if (item.Scope?.Urls != null && item.Scope.Urls.Length > 1)
						statusLogger.SetText($"Passkey '{item.Title ?? string.Empty}' specifies multiple scope URLs; only the first URL will be imported.", LogStatusType.Warning);
					foreach (var credential in item.Credentials)
					{
						if (!statusLogger.ContinueWork()) return;
						if (credential == null || !string.Equals(credential.Type, "passkey", StringComparison.Ordinal)) continue;

						statusLogger.SetText($"Validating passkey '{item.Title ?? string.Empty}'...", LogStatusType.Info);
						importedEntries.Add(new ImportedEntry
						{
							Account = account,
							ItemId = item.Id,
							Entry = CreateEntry(accountUsername, item, credential),
							TargetGroup = database.RootGroup,
						});
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
		var existingGroups = GetGroupsByUuid(database.RootGroup);
		var createdGroups = new List<GroupAddition>();
		var warnedGroupIds = new HashSet<string>(StringComparer.Ordinal);
		foreach (var account in document.Accounts)
		{
			var linkedGroups = new Dictionary<string, PwGroup>(StringComparer.Ordinal);
			if (!ResolveCollections(account.Collections, account.Id, database.RootGroup, existingGroups, createdGroups,
				linkedGroups, warnedGroupIds, statusLogger)) return;

			foreach (var importedEntry in importedEntries)
			{
				if (!ReferenceEquals(importedEntry.Account, account)) continue;
				if (linkedGroups.TryGetValue(importedEntry.ItemId, out var group))
					importedEntry.TargetGroup = group;
			}
		}

		foreach (var addition in createdGroups)
		{
			if (!statusLogger.ContinueWork()) return;
			addition.Parent.AddGroup(addition.Group, true);
		}
		foreach (var importedEntry in importedEntries)
		{
			if (!statusLogger.ContinueWork()) return;
			importedEntry.TargetGroup.AddEntry(importedEntry.Entry, true);
		}
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
			var accountId = GetRequiredString(account, "id");
			if (string.IsNullOrWhiteSpace(accountId))
				throw new SerializationException("The CXF account ID must not be empty.");
			string username = GetRequiredString(account, "username");
			string email = GetRequiredString(account, "email");
			var collectionValues = AsArray(GetValue(account, "collections"), "account collections");
			var collections = new CxfExportWriter.CxfCollection[collectionValues.Length];
			for (int i = 0; i < collectionValues.Length; i++)
				collections[i] = ParseCollection(collectionValues[i]);
			var items = AsArray(GetValue(account, "items"), "account items");
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
					Subtitle = GetString(item, "subtitle"),
					Scope = ParseCredentialScope(GetValue(item, "scope")),
					Credentials = credentials.ToArray(),
					Tags = GetStringArray(item, "tags", "item tags"),
				});
			}

			parsedAccounts.Add(new CxfExportWriter.CxfAccount
			{
				Id = accountId,
				Username = username,
				Email = email,
				Collections = collections,
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

	private static CxfExportWriter.CxfCredentialScope ParseCredentialScope(object value)
	{
		if (value == null) return null;
		var scope = AsObject(value, "credential scope");
		return new CxfExportWriter.CxfCredentialScope
		{
			Urls = GetStringArray(scope, "urls", "credential scope URLs"),
			AndroidApps = GetStringArray(scope, "androidApps", "credential scope Android apps"),
		};
	}

	private static string[] GetStringArray(Dictionary<string, object> value, string name, string description)
	{
		object arrayValue = GetValue(value, name);
		if (arrayValue == null) return Array.Empty<string>();
		var array = AsArray(arrayValue, description);
		var strings = new string[array.Length];
		for (int i = 0; i < array.Length; i++)
		{
			if (!(array[i] is string text))
				throw new SerializationException($"The CXF {description} must contain only strings.");
			strings[i] = text;
		}
		return strings;
	}

	private static CxfExportWriter.CxfCollection ParseCollection(object value)
	{
		var collection = AsObject(value, "collection");
		string id = GetRequiredString(collection, "id");
		if (string.IsNullOrWhiteSpace(id))
			throw new SerializationException("The CXF collection ID must not be empty.");
		string title = GetRequiredString(collection, "title");
		var linkedItems = AsArray(GetValue(collection, "items"), "collection items");
		var parsedLinkedItems = new CxfExportWriter.CxfLinkedItem[linkedItems.Length];
		for (int i = 0; i < linkedItems.Length; i++)
		{
			var linkedItem = AsObject(linkedItems[i], "linked item");
			string itemId = GetRequiredString(linkedItem, "item");
			if (string.IsNullOrWhiteSpace(itemId))
				throw new SerializationException("The CXF linked item ID must not be empty.");
			parsedLinkedItems[i] = new CxfExportWriter.CxfLinkedItem
			{
				Item = itemId,
				Account = GetString(linkedItem, "account"),
			};
		}

		var subCollectionsValue = GetValue(collection, "subCollections");
		var subCollectionValues = subCollectionsValue == null
			? Array.Empty<object>()
			: AsArray(subCollectionsValue, "sub-collections");
		var subCollections = new CxfExportWriter.CxfCollection[subCollectionValues.Length];
		for (int i = 0; i < subCollectionValues.Length; i++)
			subCollections[i] = ParseCollection(subCollectionValues[i]);

		long? creationAt = GetNullableInt64(collection, "creationAt");
		long? modifiedAt = GetNullableInt64(collection, "modifiedAt");
		if (creationAt < 0 || modifiedAt < 0)
			throw new SerializationException("The CXF collection timestamps must not be negative.");
		return new CxfExportWriter.CxfCollection
		{
			Id = id,
			CreationAt = creationAt,
			ModifiedAt = modifiedAt,
			Title = title,
			Subtitle = GetString(collection, "subtitle"),
			Items = parsedLinkedItems,
			SubCollections = subCollections,
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

	private static string GetRequiredString(Dictionary<string, object> value, string name)
	{
		if (!value.ContainsKey(name))
			throw new SerializationException($"The CXF account is missing the required '{name}' field.");
		return GetString(value, name)
			?? throw new SerializationException($"The CXF account field '{name}' must not be null.");
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
			entry.Strings.Set(PwDefs.NotesField, new ProtectedString(false, item.Subtitle ?? string.Empty));
			entry.Strings.Set(PwDefs.UrlField, new ProtectedString(false,
				item.Scope?.Urls != null && item.Scope.Urls.Length > 0 ? item.Scope.Urls[0] : string.Empty));
			foreach (string tag in item.Tags)
				entry.AddTag(tag);
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

	private static Dictionary<string, PwGroup> GetGroupsByUuid(PwGroup rootGroup)
	{
		var groups = new Dictionary<string, PwGroup>(StringComparer.Ordinal)
		{
			[ToBase64Url(rootGroup.Uuid.UuidBytes)] = rootGroup,
		};
		var descendants = rootGroup.GetGroups(true);
		for (uint i = 0; i < descendants.UCount; i++)
		{
			var group = descendants.GetAt(i);
			string id = ToBase64Url(group.Uuid.UuidBytes);
			if (!groups.ContainsKey(id)) groups.Add(id, group);
		}
		return groups;
	}

	private static bool ResolveCollections(CxfExportWriter.CxfCollection[] collections, string accountId, PwGroup parentGroup,
		Dictionary<string, PwGroup> groupsByUuid, List<GroupAddition> createdGroups,
		Dictionary<string, PwGroup> linkedGroups, HashSet<string> warnedGroupIds, IStatusLogger statusLogger)
	{
		foreach (var collection in collections)
		{
			if (!statusLogger.ContinueWork()) return false;
			byte[] uuidBytes = null;
			PwGroup group;
			try
			{
				try
				{
					uuidBytes = DecodeBase64Url(collection.Id, "collection ID");
				}
				catch (InvalidDataException)
				{
				}
				bool hasKeePassUuid = uuidBytes != null && uuidBytes.Length == 16 && !new PwUuid(uuidBytes).IsZero;
				string canonicalId = hasKeePassUuid ? ToBase64Url(uuidBytes) : null;
				if (hasKeePassUuid && groupsByUuid.TryGetValue(canonicalId, out group))
				{
					if (warnedGroupIds.Add(canonicalId))
						statusLogger.SetText($"A KeePass group with collection ID '{canonicalId}' already exists; it was reused without changing its title or other properties.", LogStatusType.Warning);
				}
				else
				{
					group = new PwGroup(true, true)
					{
						Name = collection.Title,
						Notes = collection.Subtitle ?? string.Empty,
					};
					if (hasKeePassUuid)
					{
						group.Uuid = new PwUuid(uuidBytes);
						groupsByUuid.Add(canonicalId, group);
					}
					if (collection.CreationAt.HasValue)
						group.CreationTime = DateTimeOffset.FromUnixTimeSeconds(collection.CreationAt.Value).UtcDateTime;
					if (collection.ModifiedAt.HasValue)
						group.LastModificationTime = DateTimeOffset.FromUnixTimeSeconds(collection.ModifiedAt.Value).UtcDateTime;
					createdGroups.Add(new GroupAddition { Parent = parentGroup, Group = group });
				}

				foreach (var linkedItem in collection.Items)
				{
					if (linkedItem.Account != null
						&& !string.Equals(linkedItem.Account, accountId, StringComparison.Ordinal)) continue;
					if (!linkedGroups.ContainsKey(linkedItem.Item))
						linkedGroups.Add(linkedItem.Item, group);
				}
			}
			finally
			{
				if (uuidBytes != null) MemUtil.ZeroByteArray(uuidBytes);
			}

			if (!ResolveCollections(collection.SubCollections, accountId, group, groupsByUuid, createdGroups,
				linkedGroups, warnedGroupIds, statusLogger)) return false;
		}
		return true;
	}

	private static string ToBase64Url(byte[] value) =>
		Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

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

	private sealed class ImportedEntry
	{
		internal CxfExportWriter.CxfAccount Account { get; set; }
		internal string ItemId { get; set; }
		internal PwEntry Entry { get; set; }
		internal PwGroup TargetGroup { get; set; }
	}

	private sealed class GroupAddition
	{
		internal PwGroup Parent { get; set; }
		internal PwGroup Group { get; set; }
	}

	private static InvalidDataException ReportInvalidDocument(IStatusLogger statusLogger, Exception exception)
	{
		const string message = "The CXF file is malformed or contains an unsupported passkey.";
		statusLogger.SetText(message, LogStatusType.Error);
		return new InvalidDataException(message, exception);
	}
}
