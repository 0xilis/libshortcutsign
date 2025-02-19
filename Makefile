buildDir = build
CC = clang

# Paths for lzfse
LZFSE_DIR = libs/lzfse
# The installation prefix (where the lzfse library will be built to)
BUILD_DIR = ../../build/lzfse
OBJ_DIR = build/obj

OS := $(shell uname)

output: $(buildDir)
	@ # Build liblzfse submodule
	@echo "building liblzfse..."
	$(MAKE) -C $(LZFSE_DIR) install INSTALL_PREFIX=$(BUILD_DIR)
	@ # Build libshortcutsign.a
	@echo "building libshortcutsign..."
	@cd build

	
	@if [ OS = "Darwin" ]; then\
		@$(CC) -c libshortcutsign.m -o build/obj/libshortcutsign.o -Os;\
	fi

	@$(CC) -c extract.c -o build/obj/extract.o -Os
	@$(CC) -c sign.c -o build/obj/sign.o -Os
	@$(CC) -c verify.c -o build/obj/verify.o -Os
	@cd ..
	@ar rcs build/usr/lib/libshortcutsign.a build/obj/*.o

$(buildDir):
	@echo "Creating Build Directory"
	mkdir -p build/usr/lib
	mkdir build/usr/bin
	mkdir build/obj
	mkdir build/lzfse
