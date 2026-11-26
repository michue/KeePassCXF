// SPDX-FileCopyrightText: Copyright (C) 2026 Michael Hüpkes
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePass.Plugins;

namespace KeePassCXF;

public sealed class KeePassCXFExt : Plugin
{
	public override bool Initialize(IPluginHost host)
	{
		if (host == null) return false;

		host.FileFormatPool.Add(new CxfFileFormatProvider());
		return true;
	}
}
