include $(TOPDIR)/rules.mk

PKG_NAME:=zroxy
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL=https://github.com/0x7a657573/zroxy.git
PKG_SOURCE_VERSION:=HEAD

PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

CMAKE_INSTALL:=1

define Package/zroxy
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=simple TLS sni proxy (sniproxy) written with pure C
endef

define Package/zroxy/description
  zroxy supports incoming HTTP/HTTPS/IMAPs… traffic and upstream to DIRECT/SOCKS5 proxy.
endef

define Package/zroxy/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/zroxy $(1)/usr/bin/zroxy
endef

$(eval $(call BuildPackage,zroxy))