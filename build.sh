mkdir build
cd build 
clang -c ../xplat.c ../sign.c ../libshortcutsign.m 
cd ..
ar rcs ./build/libshortcutsign.a ./build/libshortcutsign.o ./build/xplat.o ./build/sign.o 