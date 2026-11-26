// SPDX-FileCopyrightText: Copyright (C) 2026 Michael Hüpkes
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassCXF;
using Xunit;

namespace KeePassCXFPlugin.Tests;

public class KeePassCXFExtTests
{
	[Fact]
	public void Initialize_WithoutHost_ReturnsFalse()
	{
		var plugin = new KeePassCXFExt();

		Assert.False(plugin.Initialize(null!));
	}
}
