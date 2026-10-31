include $(TOPDIR)/rules.mk

PKG_NAME:=zroxy
PKG_VERSION:=1.4.1
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/0x7a657573/zroxy.git
PKG_SOURCE_VERSION:=231f03588ccdd31946d347aaa5b41eeed4ad9651
PKG_SOURCE_SUBMODULES:=skip
PKG_MIRROR_HASH:=skip

PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Mohammad Mazarei <mohammad.mazarei@gmail.com>
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

CMAKE_OPTIONS += -DBUILD_TESTING=OFF

define Package/zroxy
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=SNI and DNS proxy with optional SOCKS5 upstream
  DEPENDS:=+USE_GLIBC:libpthread
endef

define Package/zroxy/description
  zroxy routes HTTP and TLS connections by hostname and can provide a local
  DNS proxy. Upstream connections can be direct or use a SOCKS5 proxy.
endef

define Package/zroxy/conffiles
/etc/config/zroxy
/etc/zroxy/zroxy.conf
endef

define Package/zroxy/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/zroxy $(1)/usr/bin/zroxy
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/config $(1)/etc/zroxy
	$(INSTALL_BIN) ./files/zroxy.init $(1)/etc/init.d/zroxy
	$(INSTALL_CONF) ./files/zroxy.config $(1)/etc/config/zroxy
	$(INSTALL_CONF) ./files/zroxy.conf $(1)/etc/zroxy/zroxy.conf
endef

$(eval $(call BuildPackage,zroxy))
