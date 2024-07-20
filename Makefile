MAIN_FILE = source/main.c
MAIN_OUTPUT = output/main

all:
	gcc -g -o $(MAIN_OUTPUT) -fno-stack-protector -z execstack -no-pie -w -ldl -static -lelf $(MAIN_FILE)

clean:
	rm -f $(MAIN_OUTPUT)

run: $(MAIN_OUTPUT)
	./$(MAIN_OUTPUT)

dbg: $(MAIN_OUTPUT)
	gdb $(MAIN_OUTPUT)
