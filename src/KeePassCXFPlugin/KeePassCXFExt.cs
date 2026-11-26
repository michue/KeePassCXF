// SPDX-FileCopyrightText: Copyright (C) 2026 Michael Hüpkes
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePass.Plugins;

namespace KeePassCXF;

public sealed class KeePassCXFExt : Plugin
{
	public override bool Initialize(IPluginHost host) => host != null;

	public override void Terminate()
	{
	}
}
