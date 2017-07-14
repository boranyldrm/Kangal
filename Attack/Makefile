COMPILER = gcc

SYN_CODE = ./SYN-Flood/syn_flood.c
VLAN_CODE = ./VLAN-Hopping/vlan_hopping.c
SYN_EXE = ./SYN-Flood/exe
VLAN_EXE = ./VLAN/exe
AVOID_WARNINGS = -w
SYN_STORE = ./SYN-Flood/IPNumbersCreated.txt ./SYN-Flood/interface.conf

syn:
	$(COMPILER) $(AVOID_WARNINGS) -o $(SYN_EXE) $(SYN_CODE)

syn_run:
	sudo ./$(SYN_EXE)

syn_clean: 
	rm -f $(SYN_STORE)
	rm -f $(SYN_EXE)

vlan:
	$(COMPILER) $(AVOID_WARNINGS) -o $(VLAN_EXE) $(VLAN_CODE)

vlan_run:
	sudo ./$(VLAN_EXE)

vlan_clean:
	rm -f $(VLAN_EXE)

