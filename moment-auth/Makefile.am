COMMON_CFLAGS =			\
	-ggdb			\
	-Wno-long-long -Wall    \
	$(THIS_CFLAGS)

if PLATFORM_WIN32
    COMMON_CFLAGS += -DPLATFORM_WIN32
else
    COMMON_CFLAGS += -pthread # -rdynamic
endif

AM_CFLAGS   += -std=gnu99 $(COMMON_CFLAGS)
AM_CXXFLAGS += $(COMMON_CFLAGS)

INCLUDES = -I$(top_srcdir)

moment_auth_private_headers =

moment_auth_target_headers =

moment_authdir = $(libdir)/moment-1.0
moment_auth_LTLIBRARIES = libmoment-auth-1.0.la
libmoment_auth_1_0_la_SOURCES =	\
        mod_auth.cpp

moment_auth_extra_dist =

libmoment_auth_1_0_la_LDFLAGS = -no-undefined -version-info "0:0:0"
libmoment_auth_1_0_la_LIBADD = $(THIS_LIBS)
if PLATFORM_WIN32
libmoment_auth_1_0_la_LIBADD += -lws2_32
endif

EXTRA_DIST = $(moment_auth_private_headers) $(moment_auth_extra_dist)

