// SPDX-FileCopyrightText: Copyright (C) 2026 Michael Hüpkes
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePass.DataExchange;
using KeePassLib;
using KeePassLib.Interfaces;

namespace KeePassCXF;

internal sealed class CxfFileFormatProvider : FileFormatProvider
{
	public override bool SupportsImport => true;
	public override bool SupportsExport => true;
	public override bool ImportAppendsToRootGroupOnly => true;
	public override bool RequiresFile => true;
	public override string FormatName => "Client Exchange Format (CXF)";
	public override string DefaultExtension => "json";
	public override string ApplicationGroup => KeePass.Resources.KPRes.PasswordManagers;

	public override void Import(PwDatabase pwStorage, System.IO.Stream sInput, IStatusLogger slLogger)
	{
		CxfImportReader.Import(pwStorage, sInput, slLogger);
	}

	public override bool Export(PwExportInfo pwExportInfo, System.IO.Stream sOutput, IStatusLogger slLogger)
	{
		return CxfExportWriter.Export(pwExportInfo, sOutput, slLogger);
	}
}
