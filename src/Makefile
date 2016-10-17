# Copyright 2016 Las Venturas Playground. All rights reserved.
# Use of this source code is governed by the MIT license, a copy of which can
# be found in the LICENSE file.

$(shell [ -d "out" ] || mkdir -p out)
$(shell [ -d "out/obj/" ] || mkdir -p out/obj)

BOOSTLIBS=/usr/local/boost_1_61_0/stage/lib

CC=clang
CFLAGS=-c -m32 -fPIC -O3 -std=c++11 -w -DLINUX -DNDEBUG -I/usr/local/boost_1_61_0
OUTFILE=samp-indexer

# Catch-all
all: indexer link

# Indexer
indexer:
	$(CC) $(CFLAGS) main.cpp -o out/obj/main.o

# Link the $OUTFILE
link:
	$(CC) -O2 -m32 -fshort-wchar -lstdc++ -lm -lpthread -o out/$(OUTFILE) \
		out/obj/*.o \
		$(BOOSTLIBS)/libboost_filesystem.a \
		$(BOOSTLIBS)/libboost_program_options.a \
		$(BOOSTLIBS)/libboost_system.a \
		$(BOOSTLIBS)/libboost_thread.a

# Clean
clean:
	rm -rf out
