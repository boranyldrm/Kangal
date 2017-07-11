COMPILER = gcc

$(shell mkdir -p obj/)

OUTS = obj/defence.o obj/ip_container.o
TARGET = defence.exe

all:$(OUTS)
	$(COMPILER) -o $(TARGET) $(OUTS) -lpcap

obj/defence.o:defence.c ip_container.h
	$(COMPILER) -c defence.c -o obj/defence.o

obj/ip_container.o:ip_container.h
	$(COMPILER) -c ip_container.c -o obj/ip_container.o

clean:
	rm -f obj/*.o
	rmdir obj/
	rm -f $(TARGET)
