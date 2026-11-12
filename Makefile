# SPDX-License-Identifier: Apache-2.0
#
# LuCI web interface for the Snort 3 IDS/IPS package.

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for Snort 3 IDS/IPS
LUCI_DESCRIPTION:=Web interface for Snort 3: service status and control, \
	settings, alert summaries, local rule editing and rule updates.
LUCI_DEPENDS:=+luci-base +rpcd-mod-ucode +snort3
LUCI_PKGARCH:=all

PKG_LICENSE:=Apache-2.0
# Set a real name/address before publishing or submitting upstream.
PKG_MAINTAINER:=Your Name <you@example.com>

include ../../luci.mk

# call BuildPackage - OpenWrt buildroot signature
