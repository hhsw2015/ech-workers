windres resource.rc -o resource.o
gcc -Wall -Wextra -std=c99 -finput-charset=UTF-8 -fexec-charset=GBK -Os -s -o ech-tunnel-gui.exe resource.o main.c -luser32 -lkernel32 -lcomctl32 -lgdi32 -mwindows