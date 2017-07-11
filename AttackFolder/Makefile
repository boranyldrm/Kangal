#This is the makefile for attack.c program.
#Typing 'make' or 'make attack' will create the executable file.

COMPILER = gcc

OUTS = attack.c
TARGET = exe
AVOID_WARNINGS = -w
STORE = IPNumbersCreated.txt interface.conf

all:$(OUTS)
	$(COMPILER) $(AVOID_WARNINGS) -o $(TARGET) $(OUTS)

#Typing 'make run' runs the program.
run:
	sudo ./$(TARGET)

#Typing 'make clean' cleans the variable files.
clean: 
	rm -f $(STORE)
	rm -f $(TARGET)

