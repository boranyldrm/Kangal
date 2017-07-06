COMPILER = gcc

$(shell mkdir -p obj/)

OUTS = obj/defence.o obj/ip_container.o obj/iptables_rules.o
TARGET = exe

all:$(OUTS)
	$(COMPILER) -o $(TARGET) $(OUTS)

obj/defence.o:defence.c
	$(COMPILER) defence.c -o defence.o -lpcap

obj/ip_container.o:ip_container.c ip_container.h
	$(COMPILER) ip_container.c -o ip_container.o

obj/iptables_rules.o:iptables_rules.c iptables_rules.o
	$(COMPILER) -g -o iptables_rules.c -o iptables_rules.o -liptc -lip4tc -lip6tc -ldl

clean:
	rm -f obj/*.o
	rmdir obj/
	rm -f $(TARGET)