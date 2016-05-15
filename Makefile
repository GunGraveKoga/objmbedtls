project_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
current_dir := $(notdir $(patsubst %/,%,$(dir $(project_dir))))
build_dir=$(project_dir)build
system := $(shell uname -s)

BUILD_SYS=EMPTY
ifeq ($(filter MINGW32,$(system)),)
BUILD_SYS=MINGW32
else
ifeq ($(system),Linux)
BUILD_SYS=LINUX
endif
ifeq ($(system),Darwin)
BUILD_SYS=DARWIN
endif
endif

mbedtls_source_dir=$(project_dir)library
objmbedtls_source_dir=$(project_dir)Classes

SOURCES_CRYPTO=	aes.m		aesni.m		arc4.m		\
		asn1parse.m	asn1write.m	base64.m	\
		bignum.m	blowfish.m	camellia.m	\
		ccm.m		cipher.m	cipher_wrap.m	\
		ctr_drbg.m	des.m		dhm.m		\
		ecdh.m		ecdsa.m		ecjpake.m	\
		ecp.m						\
		ecp_curves.m	entropy.m	entropy_poll.m	\
		error.m		gcm.m		havege.m	\
		hmac_drbg.m	md.m		md2.m		\
		md4.m		md5.m		md_wrap.m	\
		memory_buffer_alloc.m		oid.m		\
		padlock.m	pem.m		pk.m		\
		pk_wrap.m	pkcs12.m	pkcs5.m		\
		pkparse.m	pkwrite.m	platform.m	\
		ripemd160.m	rsa.m		sha1.m		\
		sha256.m	sha512.m	threading.m	\
		threading_alt.m	timing.m	version.m			\
		version_features.m		xtea.m

SOURCES_CRYPTO_LIST := $(addprefix $(mbedtls_source_dir)/,$(SOURCES_CRYPTO))

SOURCES_X509=	certs.m		pkcs11.m	x509.m		\
		x509_create.m	x509_crl.m	x509_crt.m	\
		x509_csr.m	x509write_crt.m	x509write_csr.m

SOURCES_X509_LIST := $(addprefix $(mbedtls_source_dir)/,$(SOURCES_X509))

SOURCES_TLS=	debug.m		net.m		ssl_cache.m	\
		ssl_ciphersuites.m		ssl_cli.m	\
		ssl_cookie.m	ssl_srv.m	ssl_ticket.m	\
		ssl_tls.m

SOURCES_TLS_LIST := $(addprefix $(mbedtls_source_dir)/,$(SOURCES_TLS))

SOURCES_OBJFW_SSL_SOCKET= MBEDX509Certificate.m MBEDSSL.m MBEDCRL.m 	\
						MBEDPKey.m MBEDSSLSocket.m SSLAcceptFailedException.m 	\
						SSLCertificateVerificationFailedException.m SSLCertificationAuthorityMissingException.m SSLConnectionFailedException.m 	\
						SSLReadFailedException.m SSLWriteFailedException.m MBEDTLSException.m

SOURCES_OBJFW_SSL_SOCKET_LIST := $(addprefix $(objmbedtls_source_dir)/,$(SOURCES_OBJFW_SSL_SOCKET))					

OBJS_CRYPTO=	aes.lib.o		aesni.lib.o		arc4.lib.o		\
		asn1parse.lib.o	asn1write.lib.o	base64.lib.o	\
		bignum.lib.o	blowfish.lib.o	camellia.lib.o	\
		ccm.lib.o		cipher.lib.o	cipher_wrap.lib.o	\
		ctr_drbg.lib.o	des.lib.o		dhm.lib.o		\
		ecdh.lib.o		ecdsa.lib.o		ecjpake.lib.o	\
		ecp.lib.o						\
		ecp_curves.lib.o	entropy.lib.o	entropy_poll.lib.o	\
		error.lib.o		gcm.lib.o		havege.lib.o	\
		hmac_drbg.lib.o	md.lib.o		md2.lib.o		\
		md4.lib.o		md5.lib.o		md_wrap.lib.o	\
		memory_buffer_alloc.lib.o		oid.lib.o		\
		padlock.lib.o	pem.lib.o		pk.lib.o		\
		pk_wrap.lib.o	pkcs12.lib.o	pkcs5.lib.o		\
		pkparse.lib.o	pkwrite.lib.o	platform.lib.o	\
		ripemd160.lib.o	rsa.lib.o		sha1.lib.o		\
		sha256.lib.o	sha512.lib.o	threading.lib.o	\
		threading_alt.lib.o	timing.lib.o	version.lib.o			\
		version_features.lib.o		xtea.lib.o

OBJS_CRYPTO_LIST := $(addprefix $(build_dir)/,$(OBJS_CRYPTO))

OBJS_X509=	certs.lib.o		pkcs11.lib.o	x509.lib.o		\
		x509_create.lib.o	x509_crl.lib.o	x509_crt.lib.o	\
		x509_csr.lib.o	x509write_crt.lib.o	x509write_csr.lib.o

OBJS_X509_LIST := $(addprefix $(build_dir)/,$(OBJS_X509))

OBJS_TLS=	debug.lib.o		net.lib.o		ssl_cache.lib.o	\
		ssl_ciphersuites.lib.o		ssl_cli.lib.o	\
		ssl_cookie.lib.o	ssl_srv.lib.o	ssl_ticket.lib.o	\
		ssl_tls.lib.o

OBJS_TLS_LIST := $(addprefix $(build_dir)/,$(OBJS_TLS))

CC=i686-w64-mingw32-objfw-compile
CHDIR=cd
MOVE=mv
COPY=cp
DELETE=rm -rf
AR=ar

MBEDTLS_X509=mbedx509
MBEDTLS_TLS=mbedtls
MBEDTLS_CRYPTO=mbedcrypto
OBJFW_SSL_SOCKET=tlssocket

ifeq ($(BUILD_SYS), MINGW32)
EXECUTABLE_EXTANSION=.exe
else
EXECUTABLE_EXTANSION=
endif

SOEXT_TLS=
SOEXT_X509=
SOEXT_CRYPTO=

ifeq ($(BUILD_SYS), MINGW32)
SHARED_LIBRARY_EXTANSION=.dll
endif

ifeq ($(BUILD_SYS), DARWIN)
SHARED_LIBRARY_EXTANSION=.dylib
endif

ifeq ($(BUILD_SYS), LINUX)
SHARED_LIBRARY_EXTANSION=.so
SOEXT_TLS=so.10
SOEXT_X509=so.0
SOEXT_CRYPTO=so.0
endif

ifeq ($(BUILD_SYS), EMPTY)
$(error Unsuported OS $(BUILD_SYS))
endif

STATIC_LIBRARY_EXTENSION=.a
LIBRARY_PREFIX=lib


EXECUTABLE_LIBS=-l$(MBEDTLS_CRYPTO) -l$(MBEDTLS_X509) -l$(MBEDTLS_TLS)
EXECUTEBLE_LIBDIR=$(build_dir)
PROJECT_LIBS_DIR=$(build_dir)

MBEDTLS_INCLUDES_DIR=$(project_dir)include

.SILENT:

.PHONY: all static shared clean

ifndef SHARED
all: static sslsocket
else
all: shared static sslsocket
endif

MBEDTLS_CRYPTO_STATIC=$(LIBRARY_PREFIX)$(MBEDTLS_CRYPTO)$(STATIC_LIBRARY_EXTENSION)
MBEDTLS_X509_STATIC=$(LIBRARY_PREFIX)$(MBEDTLS_X509)$(STATIC_LIBRARY_EXTENSION)
MBEDTLS_TLS_STATIC=$(LIBRARY_PREFIX)$(MBEDTLS_TLS)$(STATIC_LIBRARY_EXTENSION)

MBEDTLS_CRYPTO_SHARED=$(LIBRARY_PREFIX)$(MBEDTLS_CRYPTO)$(SHARED_LIBRARY_EXTANSION)
MBEDTLS_X509_SHARED=$(LIBRARY_PREFIX)$(MBEDTLS_X509)$(SHARED_LIBRARY_EXTANSION)
MBEDTLS_TLS_SHARED=$(LIBRARY_PREFIX)$(MBEDTLS_TLS)$(SHARED_LIBRARY_EXTANSION)

OBJFW_SSL_SOCKET_LIB=$(LIBRARY_PREFIX)$(OBJFW_SSL_SOCKET)$(SHARED_LIBRARY_EXTANSION)

ifeq ($(BUILD_SYS), MINGW32)
MBEDTLS_CRYPTO_SHARED_EXPORT=$(MBEDTLS_CRYPTO_SHARED)$(STATIC_LIBRARY_EXTENSION)
MBEDTLS_X509_SHARED_EXPORT=$(MBEDTLS_X509_SHARED)$(STATIC_LIBRARY_EXTENSION)
MBEDTLS_TLS_SHARED_EXPORT=$(MBEDTLS_TLS_SHARED)$(STATIC_LIBRARY_EXTENSION)
OBJFW_SSL_SOCKET_LIB_EXPORT=$(OBJFW_SSL_SOCKET_LIB)$(STATIC_LIBRARY_EXTENSION)
else
MBEDTLS_CRYPTO_SHARED_EXPORT=
MBEDTLS_X509_SHARED_EXPORT=
MBEDTLS_TLS_SHARED_EXPORT=
OBJFW_SSL_SOCKET_LIB_EXPORT=
endif

static: $(MBEDTLS_CRYPTO_STATIC) $(MBEDTLS_X509_STATIC) $(MBEDTLS_TLS_STATIC)

shared: $(MBEDTLS_CRYPTO_SHARED) $(MBEDTLS_X509_SHARED) $(MBEDTLS_TLS_SHARED)

sslsocket: $(OBJFW_SSL_SOCKET_LIB)


$(MBEDTLS_CRYPTO_SHARED): $(SOURCES_CRYPTO_LIST)
	echo -e "\e[1;34mBuilding $(MBEDTLS_CRYPTO_SHARED)...\e[0m"
	$(CHDIR) $(mbedtls_source_dir) && \
	$(CC) --builddir $(build_dir) $(SOURCES_CRYPTO) -I$(MBEDTLS_INCLUDES_DIR) --lib 0.9 -o $(MBEDTLS_CRYPTO) -lwinmm -lgdi32 && \
	$(MOVE) $(MBEDTLS_CRYPTO_SHARED) $(build_dir) && \
	$(MOVE) $(MBEDTLS_CRYPTO_SHARED_EXPORT) $(build_dir) && \
	$(COPY) $(build_dir)/$(MBEDTLS_CRYPTO_SHARED) $(project_dir)
	echo -e "\e[1;34mDone.\e[0m"

$(MBEDTLS_CRYPTO_STATIC): $(MBEDTLS_CRYPTO_SHARED) $(OBJS_CRYPTO_LIST)
	echo -e "\e[1;34mBuilding $(MBEDTLS_CRYPTO_STATIC)...\e[0m"
	$(CHDIR) $(build_dir) && \
	$(AR) rc $(MBEDTLS_CRYPTO_STATIC) $(OBJS_CRYPTO) && \
	$(AR) s $(MBEDTLS_CRYPTO_STATIC) && \
	$(COPY) $(build_dir)/$(MBEDTLS_CRYPTO_STATIC) $(project_dir)
	echo -e "\e[1;34mDone.\e[0m"

$(MBEDTLS_X509_SHARED): $(SOURCES_X509_LIST)
	echo -e "\e[1;34mBuilding $(MBEDTLS_X509_SHARED)...\e[0m"
	$(CHDIR) $(mbedtls_source_dir) && \
	$(CC) --builddir $(build_dir) $(SOURCES_X509) -I$(MBEDTLS_INCLUDES_DIR) --lib 0.9 -o $(MBEDTLS_X509) -lwinmm -lgdi32 -L$(build_dir) -l$(MBEDTLS_CRYPTO) && \
	$(MOVE) $(MBEDTLS_X509_SHARED) $(build_dir) && \
	$(MOVE) $(MBEDTLS_X509_SHARED_EXPORT) $(build_dir) && \
	$(COPY) $(build_dir)/$(MBEDTLS_X509_SHARED) $(project_dir)
	echo -e "\e[1;34mDone.\e[0m"

$(MBEDTLS_X509_STATIC): $(MBEDTLS_X509_SHARED) $(OBJS_X509_LIST)
	echo -e "\e[1;34mBuilding $(MBEDTLS_X509_STATIC)...\e[0m"
	$(CHDIR) $(build_dir) && \
	$(AR) rc $(MBEDTLS_X509_STATIC) $(OBJS_X509) && \
	$(AR) s $(MBEDTLS_X509_STATIC) && \
	$(COPY) $(build_dir)/$(MBEDTLS_X509_STATIC) $(project_dir)
	echo -e "\e[1;34mDone.\e[0m"

$(MBEDTLS_TLS_SHARED): $(SOURCES_TLS_LIST)
	echo -e "\e[1;34mBuilding $(MBEDTLS_TLS_SHARED)...\e[0m"
	$(CHDIR) $(mbedtls_source_dir) && \
	$(CC) --builddir $(build_dir) $(SOURCES_TLS) -I$(MBEDTLS_INCLUDES_DIR) --lib 0.9 -o $(MBEDTLS_TLS) -lwinmm -lgdi32 -L$(build_dir) -l$(MBEDTLS_CRYPTO) -l$(MBEDTLS_X509) && \
	$(MOVE) $(MBEDTLS_TLS_SHARED) $(build_dir) && \
	$(MOVE) $(MBEDTLS_TLS_SHARED_EXPORT) $(build_dir) && \
	$(COPY) $(build_dir)/$(MBEDTLS_TLS_SHARED) $(project_dir)
	echo -e "\e[1;34mDone.\e[0m"

$(MBEDTLS_TLS_STATIC): $(MBEDTLS_TLS_SHARED) $(OBJS_TLS_LIST)
	echo -e "\e[1;34mBuilding $(MBEDTLS_TLS_STATIC)...\e[0m"
	$(CHDIR) $(build_dir) && \
	$(AR) rc $(MBEDTLS_TLS_STATIC) $(OBJS_CRYPTO) && \
	$(AR) s $(MBEDTLS_TLS_STATIC) && \
	$(COPY) $(build_dir)/$(MBEDTLS_TLS_STATIC) $(project_dir)
	echo -e "\e[1;34mDone.\e[0m"

$(OBJFW_SSL_SOCKET_LIB): $(MBEDTLS_CRYPTO_SHARED) $(MBEDTLS_X509_SHARED) $(MBEDTLS_TLS_SHARED) $(MBEDTLS_CRYPTO_STATIC) $(MBEDTLS_X509_STATIC) $(MBEDTLS_TLS_STATIC) $(SOURCES_OBJFW_SSL_SOCKET_LIST)
	echo -e "\e[1;34mBuilding $(OBJFW_SSL_SOCKET_LIB)...\e[0m"
	$(CHDIR) $(objmbedtls_source_dir) && \
	$(COPY) $(build_dir)/$(MBEDTLS_TLS_STATIC) $(objmbedtls_source_dir) && \
	$(COPY) $(build_dir)/$(MBEDTLS_X509_STATIC) $(objmbedtls_source_dir) && \
	$(COPY) $(build_dir)/$(MBEDTLS_CRYPTO_STATIC) $(objmbedtls_source_dir) && \
	$(CC) --builddir $(build_dir) $(SOURCES_OBJFW_SSL_SOCKET) -I$(MBEDTLS_INCLUDES_DIR) -I$(objmbedtls_source_dir) --lib 0.9 -o $(OBJFW_SSL_SOCKET) -L$(build_dir) -l$(MBEDTLS_CRYPTO) -l$(MBEDTLS_X509) -l$(MBEDTLS_TLS) && \
	$(MOVE) $(OBJFW_SSL_SOCKET_LIB) $(build_dir) && \
	$(MOVE) $(OBJFW_SSL_SOCKET_LIB_EXPORT) $(build_dir) && \
	$(DELETE) $(objmbedtls_source_dir)/$(MBEDTLS_TLS_STATIC) && \
	$(DELETE) $(objmbedtls_source_dir)/$(MBEDTLS_X509_STATIC) && \
	$(DELETE) $(objmbedtls_source_dir)/$(MBEDTLS_CRYPTO_STATIC)
	echo -e "\e[1;34mDone.\e[0m"

clean:
	$(DELETE) $(build_dir)/*.o
	$(DELETE) $(build_dir)/*.a
	$(DELETE) $(build_dir)/*.dll
	$(DELETE) $(build_dir)/*.exe
	echo -e "\e[1;34mAll clean.\e[0m"