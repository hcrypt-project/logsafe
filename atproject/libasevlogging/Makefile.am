#######################################
# The list of libraries we are building seperated by spaces.
# The 'lib_' indicates that these build products will be installed
# in the $(libdir) directory. For example /usr/lib
lib_LTLIBRARIES = libasevlogging.la

#######################################
# Build information for each library

# Sources for libasevlogging
libasevlogging_la_SOURCES = libasevlogging.cpp amq_producer.cpp aesstuff.cpp rsastuff.cpp shastuff.cpp asevlog.cpp

# Linker options libTestProgram
libasevlogging_la_LDFLAGS = -lssl -lcrypto -lactivemq-cpp

# Compiler options. Here we are adding the include directory
# to be searched for headers included in the source code.
libasevlogging_la_CPPFLAGS = -I$(top_srcdir)/include -I/usr/local/include/activemq-cpp-3.5.0

