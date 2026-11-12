# SPDX-License-Identifier: Apache-2.0
#
# LuCI web interface for the Snort 3 IDS/IPS package.

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for Snort 3 IDS/IPS
LUCI_DESCRIPTION:=Web interface for Snort 3: service status and control, \
	settings, alert summaries, local rule editing and rule updates.
LUCI_DEPENDS:=+luci-base +rpcd-mod-ucode +snort3
LUCI_PKGARCH:=all

# Explicit version for standalone releases; luci.mk would otherwise derive
# one from the git history of the LuCI feed.
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=little-schlapps <little-schlapps@users.noreply.github.com>
# luci.mk writes these into the package metadata (it ignores PKG_MAINTAINER)
LUCI_MAINTAINER:=$(PKG_MAINTAINER)
LUCI_URL:=https://github.com/little-schlapps/luci-app-snort

include ../../luci.mk

# call BuildPackage - OpenWrt buildroot signature
