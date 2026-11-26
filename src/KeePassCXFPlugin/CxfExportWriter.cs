// SPDX-FileCopyrightText: Copyright (C) 2026 Michael Hüpkes
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Xml;
using KeePass.DataExchange;
using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Security;
using KeePassLib.Utility;

namespace KeePassCXF;

internal static class CxfExportWriter
{
	private const string FieldCredentialId = "KPEX_PASSKEY_CREDENTIAL_ID";
	private const string FieldPrivateKey = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
	private const string FieldRelyingParty = "KPEX_PASSKEY_RELYING_PARTY";
	private const string FieldUserHandle = "KPEX_PASSKEY_USER_HANDLE";
	private const string FieldUsername = "KPEX_PASSKEY_USERNAME";
	private const string ExporterRpId = "keepass.info";
	private const string ExporterDisplayName = "KeePassCXF";

	internal static bool Export(PwExportInfo exportInfo, Stream output, IStatusLogger statusLogger)
	{
		var database = exportInfo.ContextDatabase;
		string databaseFileName = database == null ? null : Path.GetFileName(database.IOConnectionInfo.Path);
		if (database == null || string.IsNullOrEmpty(databaseFileName))
		{
			statusLogger.SetText("The KeePass database context or file name is unavailable.", LogStatusType.Error);
			return false;
		}

		statusLogger.SetText("Collecting passkeys for CXF export...", LogStatusType.Info);
		var items = new List<CxfItem>();
		if (!CollectGroupItems(exportInfo.DataGroup, items, statusLogger, out var error))
		{
			if (error != null) statusLogger.SetText(error, LogStatusType.Error);
			return false;
		}
		if (!TryCreateCollections(exportInfo.DataGroup, statusLogger, out var collections, out error))
		{
			if (error != null) statusLogger.SetText(error, LogStatusType.Error);
			return false;
		}

		var account = new CxfAccount
		{
			Id = ToBase64Url(database.RootGroup.Uuid.UuidBytes),
			Username = databaseFileName,
			Email = string.Empty,
			Collections = collections,
			Items = items.ToArray(),
		};
		var payload = new CxfHeader
		{
			Version = new CxfVersion { Major = 1, Minor = 0 },
			ExporterRpId = ExporterRpId,
			ExporterDisplayName = ExporterDisplayName,
			Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
			Accounts = new[] { account },
		};

		statusLogger.SetText($"Writing {items.Count} passkey(s) in CXF format...", LogStatusType.Info);
		var serializer = new DataContractJsonSerializer(typeof(CxfHeader));
		using (var json = new MemoryStream())
		{
			using (XmlDictionaryWriter writer = JsonReaderWriterFactory.CreateJsonWriter(json, Encoding.UTF8, false, true))
			{
				serializer.WriteObject(writer, payload);
				writer.Flush();
			}
			var buffer = json.GetBuffer();
			try
			{
				output.Write(buffer, 0, checked((int)json.Length));
			}
			finally
			{
				Array.Clear(buffer, 0, buffer.Length);
			}
		}

		statusLogger.SetText($"Exported {items.Count} passkey(s).", LogStatusType.Info);
		return true;
	}

	private static bool CollectGroupItems(PwGroup group, List<CxfItem> items, IStatusLogger statusLogger, out string error)
	{
		error = null;
		for (uint i = 0; i < group.Entries.UCount; i++)
		{
			if (!statusLogger.ContinueWork()) return false;
			var entry = group.Entries.GetAt(i);
			if (!HasPasskey(entry)) continue;
			if (!TryCreateItem(entry, out var item, out error)) return false;
			items.Add(item);
		}
		for (uint i = 0; i < group.Groups.UCount; i++)
			if (!CollectGroupItems(group.Groups.GetAt(i), items, statusLogger, out error)) return false;
		return true;
	}

	private static bool TryCreateCollections(PwGroup parentGroup, IStatusLogger statusLogger,
		out CxfCollection[] collections, out string error)
	{
		collections = new CxfCollection[parentGroup.Groups.UCount];
		error = null;
		for (uint i = 0; i < parentGroup.Groups.UCount; i++)
		{
			if (!statusLogger.ContinueWork()) return false;
			var group = parentGroup.Groups.GetAt(i);
			var linkedItems = new List<CxfLinkedItem>();
			for (uint entryIndex = 0; entryIndex < group.Entries.UCount; entryIndex++)
			{
				var entry = group.Entries.GetAt(entryIndex);
				if (HasPasskey(entry)) linkedItems.Add(new CxfLinkedItem { Item = ToBase64Url(entry.Uuid.UuidBytes) });
			}

			if (!TryCreateCollections(group, statusLogger, out var subCollections, out error)) return false;
			collections[i] = new CxfCollection
			{
				Id = ToBase64Url(group.Uuid.UuidBytes),
				CreationAt = ToOptionalUnixTimeSeconds(group.CreationTime),
				ModifiedAt = ToOptionalUnixTimeSeconds(group.LastModificationTime),
				Title = group.Name,
				Subtitle = string.IsNullOrWhiteSpace(group.Notes) ? null : group.Notes,
				Items = linkedItems.ToArray(),
				SubCollections = subCollections.Length == 0 ? null : subCollections,
			};
		}
		return true;
	}

	private static bool HasPasskey(PwEntry entry) =>
		entry.Strings.Exists(FieldCredentialId)
		&& !string.IsNullOrEmpty(entry.Strings.ReadSafe(FieldCredentialId));

	private static bool TryCreateItem(PwEntry entry, out CxfItem item, out string error)
	{
		item = null;
		error = null;
		var credentialId = entry.Strings.ReadSafe(FieldCredentialId);
		var relyingParty = entry.Strings.ReadSafe(FieldRelyingParty);
		var privateKey = entry.Strings.GetSafe(FieldPrivateKey);
		if (string.IsNullOrEmpty(relyingParty))
		{
			error = $"Passkey entry '{entry.Strings.ReadSafe(PwDefs.TitleField)}' has no relying party ID and was not exported.";
			return false;
		}
		if (privateKey == null || privateKey.IsEmpty)
		{
			error = $"Passkey entry '{entry.Strings.ReadSafe(PwDefs.TitleField)}' has no private key and was not exported.";
			return false;
		}

		byte[] der = null;
		try
		{
			der = DecodePkcs8PrivateKey(privateKey);
			if (der.Length == 0)
				throw new InvalidDataException("The PKCS#8 private key is empty.");

			var passkey = new CxfPasskey
			{
				Type = "passkey",
				CredentialId = credentialId,
				RpId = relyingParty,
				Username = entry.Strings.ReadSafe(FieldUsername),
				UserDisplayName = string.Empty,
				UserHandle = entry.Strings.ReadSafe(FieldUserHandle),
				Key = ToBase64Url(der),
			};
			item = new CxfItem
			{
				Id = ToBase64Url(entry.Uuid.UuidBytes),
				CreationAt = ToUnixTimeSeconds(entry.CreationTime),
				ModifiedAt = ToUnixTimeSeconds(entry.LastModificationTime),
				Title = entry.Strings.ReadSafe(PwDefs.TitleField),
				Credentials = new[] { passkey },
			};
			return true;
		}
		catch (FormatException)
		{
			error = $"Passkey entry '{entry.Strings.ReadSafe(PwDefs.TitleField)}' has an invalid PKCS#8 private key and was not exported.";
			return false;
		}
		catch (InvalidDataException)
		{
			error = $"Passkey entry '{entry.Strings.ReadSafe(PwDefs.TitleField)}' has an invalid PKCS#8 private key and was not exported.";
			return false;
		}
		finally
		{
			if (der != null) MemUtil.ZeroByteArray(der);
		}
	}

	private static long? ToOptionalUnixTimeSeconds(DateTime value)
	{
		long timestamp = ToUnixTimeSeconds(value);
		return timestamp < 0 ? (long?)null : timestamp;
	}

	private static long ToUnixTimeSeconds(DateTime value)
	{
		var utc = value.Kind == DateTimeKind.Local
			? value.ToUniversalTime()
			: DateTime.SpecifyKind(value, DateTimeKind.Utc);
		return new DateTimeOffset(utc).ToUnixTimeSeconds();
	}

	private static byte[] DecodePkcs8PrivateKey(ProtectedString protectedKey)
	{
		byte[] pem = protectedKey.ReadUtf8();
		char[] base64 = null;
		try
		{
			byte[] begin = Encoding.ASCII.GetBytes("-----BEGIN PRIVATE KEY-----");
			byte[] end = Encoding.ASCII.GetBytes("-----END PRIVATE KEY-----");
			int bodyStart = IndexOf(pem, begin);
			if (bodyStart < 0)
				throw new InvalidDataException("Expected an unencrypted PKCS#8 PEM private key.");
			bodyStart += begin.Length;
			int bodyEnd = IndexOf(pem, end, bodyStart);
			if (bodyEnd < 0)
				throw new InvalidDataException("The PKCS#8 PEM footer is missing.");

			base64 = new char[bodyEnd - bodyStart];
			int count = 0;
			for (int i = bodyStart; i < bodyEnd; i++)
			{
				byte b = pem[i];
				if (b == '\r' || b == '\n' || b == ' ' || b == '\t') continue;
				if (b > 0x7f) throw new InvalidDataException("The PKCS#8 PEM body is not ASCII.");
				base64[count++] = (char)b;
			}
			return Convert.FromBase64CharArray(base64, 0, count);
		}
		finally
		{
			MemUtil.ZeroByteArray(pem);
			if (base64 != null) Array.Clear(base64, 0, base64.Length);
		}
	}

	private static int IndexOf(byte[] data, byte[] value, int start = 0)
	{
		for (int i = start; i <= data.Length - value.Length; i++)
		{
			int j = 0;
			while (j < value.Length && data[i + j] == value[j]) j++;
			if (j == value.Length) return i;
		}
		return -1;
	}

	private static string ToBase64Url(byte[] value) =>
		Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

	[DataContract]
	internal sealed class CxfHeader
	{
		[DataMember(Name = "version", Order = 0)] public CxfVersion Version { get; set; }
		[DataMember(Name = "exporterRpId", Order = 1)] public string ExporterRpId { get; set; }
		[DataMember(Name = "exporterDisplayName", Order = 2)] public string ExporterDisplayName { get; set; }
		[DataMember(Name = "timestamp", Order = 3)] public long Timestamp { get; set; }
		[DataMember(Name = "accounts", Order = 4)] public CxfAccount[] Accounts { get; set; }
	}

	[DataContract]
	internal sealed class CxfVersion
	{
		[DataMember(Name = "major", Order = 0)] public int Major { get; set; }
		[DataMember(Name = "minor", Order = 1)] public int Minor { get; set; }
	}

	[DataContract]
	internal sealed class CxfAccount
	{
		[DataMember(Name = "id", Order = 0)] public string Id { get; set; }
		[DataMember(Name = "username", Order = 1)] public string Username { get; set; }
		[DataMember(Name = "email", Order = 2)] public string Email { get; set; }
		[DataMember(Name = "collections", Order = 3)] public CxfCollection[] Collections { get; set; }
		[DataMember(Name = "items", Order = 4)] public CxfItem[] Items { get; set; }
	}

	[DataContract]
	internal sealed class CxfCollection
	{
		[DataMember(Name = "id", Order = 0)] public string Id { get; set; }
		[DataMember(Name = "creationAt", Order = 1, EmitDefaultValue = false)] public long? CreationAt { get; set; }
		[DataMember(Name = "modifiedAt", Order = 2, EmitDefaultValue = false)] public long? ModifiedAt { get; set; }
		[DataMember(Name = "title", Order = 3)] public string Title { get; set; }
		[DataMember(Name = "subtitle", Order = 4, EmitDefaultValue = false)] public string Subtitle { get; set; }
		[DataMember(Name = "items", Order = 5)] public CxfLinkedItem[] Items { get; set; }
		[DataMember(Name = "subCollections", Order = 6, EmitDefaultValue = false)] public CxfCollection[] SubCollections { get; set; }
	}

	[DataContract]
	internal sealed class CxfLinkedItem
	{
		[DataMember(Name = "item", Order = 0)] public string Item { get; set; }
	}

	[DataContract]
	internal sealed class CxfItem
	{
		[DataMember(Name = "id", Order = 0)] public string Id { get; set; }
		[DataMember(Name = "creationAt", Order = 1, EmitDefaultValue = false)] public long? CreationAt { get; set; }
		[DataMember(Name = "modifiedAt", Order = 2, EmitDefaultValue = false)] public long? ModifiedAt { get; set; }
		[DataMember(Name = "title", Order = 3)] public string Title { get; set; }
		[DataMember(Name = "credentials", Order = 4)] public CxfPasskey[] Credentials { get; set; }
	}

	[DataContract]
	internal sealed class CxfPasskey
	{
		[DataMember(Name = "type", Order = 0)] public string Type { get; set; }
		[DataMember(Name = "credentialId", Order = 1)] public string CredentialId { get; set; }
		[DataMember(Name = "rpId", Order = 2)] public string RpId { get; set; }
		[DataMember(Name = "username", Order = 3)] public string Username { get; set; }
		[DataMember(Name = "userDisplayName", Order = 4)] public string UserDisplayName { get; set; }
		[DataMember(Name = "userHandle", Order = 5)] public string UserHandle { get; set; }
		[DataMember(Name = "key", Order = 6)] public string Key { get; set; }
	}
}
