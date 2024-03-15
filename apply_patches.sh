cd lib/libwally-embedded
patch -p 1 -i ../../patches/libwally_embedded-1.patch
cd libwally-core
patch -p 1 -i ../../../patches/libwally_core-1.patch
cd ../../..