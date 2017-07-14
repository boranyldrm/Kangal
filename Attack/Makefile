SYN_EXE = ./SYN-Flood/exe
VLAN_EXE = ./VLAN-Hopping/exe
CFLAGS += -w
SYN_STORE = ./SYN-Flood/IPNumbersCreated.txt ./SYN-Flood/interface.conf

syn: SYN-Flood/syn_flood.o
	$(CC) -o $(SYN_EXE) $^

syn_run:
	sudo ./$(SYN_EXE)

syn_clean: 
	rm -f $(SYN_STORE)
	rm -f $(SYN_EXE)

vlan: VLAN-Hopping/vlan_hopping.o
	$(CC) -o $(VLAN_EXE) $^ -lpcap

vlan_run:
	sudo ./$(VLAN_EXE)

vlan_clean:
	rm -f $(VLAN_EXE)

clean:
	rm -rf $(VLAN_EXE) $(SYN_EXE) $(SYN_STORE)

