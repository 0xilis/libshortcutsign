buildDir = build
CC = clang
CFLAGS = -std=c89 -I../build/lzfse/include -I../build/libzbitmap/include -I../ -g -fsanitize=address

LIBSHORTCUTSIGN_DIR = ../

output: $(buildDir)
	@ # Build libshortcutsign
	@echo "building libshortcutsign..."
	$(MAKE) -C $(LIBSHORTCUTSIGN_DIR)

	@ # Build tests
	@echo "building tests..."
	@$(CC) *.c ../build/usr/lib/libshortcutsign.a -L../build/lzfse/lib -L../libs/libNeoAppleArchive/build/libzbitmap/lib -L../libs/libNeoAppleArchive/build/usr/lib -o build/tests -llzfse -lNeoAppleArchive -lzbitmap -lz -lssl -lcrypto -lplist-2.0 $(CFLAGS)

$(buildDir):
	@echo "Creating Build Directory"
	mkdir -p build/obj