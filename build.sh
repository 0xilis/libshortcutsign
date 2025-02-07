mkdir build
cd build
clang -c -framework Foundation -lAppleArchive -framework Security ../xplat.c ../libshortcutsign.m
cd ..
ar rcs ./build/libshortcutsign.a ./build/libshortcutsign.o ./build/xplat.o