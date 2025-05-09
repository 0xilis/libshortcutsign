buildDir = build/obj
CC = clang
CFLAGS += -Os -Wall -Wpedantic -Wextra -fPIC -Ilibs/libNeoAppleArchive/libNeoAppleArchive -Ibuild/lzfse/include/

# Paths for lzfse
LZFSE_DIR = libs/lzfse
# The installation prefix (where the lzfse library will be built to)
BUILD_DIR = ../../build/lzfse
OBJ_DIR = build/obj

NEOAPPLEARCHIVE_DIR = libs/libNeoAppleArchive

OS := $(shell uname)

VERSION_SCRIPT = EXPORTS

DEBUG ?= 0

ifeq ($(DEBUG), 1)
  CFLAGS += -g -fsanitize=address
endif

output: $(buildDir)
	@ # Build liblzfse submodule
	@echo "building liblzfse..."
	$(MAKE) -C $(LZFSE_DIR) install INSTALL_PREFIX=$(BUILD_DIR)

	@ # Build libNeoAppleArchive submodule
	@echo "building libNeoAppleArchive..."
	$(MAKE) -C $(NEOAPPLEARCHIVE_DIR)

	@ # Build libshortcutsign.a
	@echo "building libshortcutsign..."
	@cd build

	@$(CC) -c extract.c -o build/obj/extract.o $(CFLAGS)
	@$(CC) -c sign.c -o build/obj/sign.o $(CFLAGS)
	@$(CC) -c verify.c -o build/obj/verify.o $(CFLAGS)
	@$(CC) -c res.c -o build/obj/res.o $(CFLAGS)
	@cd ..
	@ar rcs build/usr/lib/libshortcutsign.a build/obj/*.o

	@# Create shared library and use version script
	@if [ "$(OS)" = "Darwin" ]; then\
		$(CC) -shared -o build/usr/lib/libshortcutsign.dylib build/obj/*.o -Lbuild/lzfse/lib -Llibs/libNeoAppleArchive/build/libzbitmap/lib -Llibs/libNeoAppleArchive/build/usr/lib -lNeoAppleArchive -lzbitmap -llzfse -lz -lssl -lcrypto -lplist-2.0 $(CFLAGS) -Wl,-install_name,@rpath/libshortcutsign.dylib -Wl,-exported_symbols_list,$(VERSION_SCRIPT);\
	else\
		$(CC) -shared -o build/usr/lib/libshortcutsign.so build/obj/*.o -Lbuild/lzfse/lib -Llibs/libNeoAppleArchive/build/libzbitmap/lib -Llibs/libNeoAppleArchive/build/usr/lib -lNeoAppleArchive -lzbitmap -llzfse -lz -lssl -lcrypto -lplist-2.0 $(CFLAGS);\
	fi

$(buildDir):
	@echo "Creating Build Directory"
	mkdir -p build/usr/lib
	mkdir -p build/usr/bin
	mkdir -p build/obj
	mkdir -p build/lzfse

clean:
	@echo "Cleaning build files..."
	@rm -rf build/obj

.PHONY: output clean