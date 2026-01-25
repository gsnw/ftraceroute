AC_PREREQ([2.69])
AC_INIT([ftraceroute], [0.2])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# We now check whether a file exists in the src folder
AC_CONFIG_SRCDIR([src/ftraceroute.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h netinet/ip.h netinet/ip_icmp.h netinet/icmp6.h netinet/ip6.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([getaddrinfo gettimeofday memset socket strerror])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT