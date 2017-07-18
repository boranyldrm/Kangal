SYN_EXE = ./SYN-Flood/exe
VLAN_EXE = ./VLAN-Hopping/exe
CFLAGS += -w
SYN_STORE = ./SYN-Flood/IPNumbersCreated.txt ./SYN-Flood/interface.conf
 
syn: SYN-Flood/syn_flood.o
	$(CC) -o $(SYN_EXE) $^

synrun:
	sudo ./$(SYN_EXE)

synclean: 
	rm -f $(SYN_STORE)
	rm -f $(SYN_EXE)

vlan: VLAN-Hopping/vlan_hopping.o
	$(CC) -o $(VLAN_EXE) $^ -lpcap

vlanrun:
	sudo ./$(VLAN_EXE)

vlanclean:
	rm -f $(VLAN_EXE)

clean:
	rm -rf $(VLAN_EXE) $(SYN_EXE) $(SYN_STORE)

