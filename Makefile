MAIN_FILE = source/main.c
MAIN_OUTPUT = output/main

all:
	gcc -g -o $(MAIN_OUTPUT) -fno-stack-protector -z execstack -no-pie -w -ldl $(MAIN_FILE)

clean:
	rm -f $(MAIN_OUTPUT)

run: $(MAIN_OUTPUT)
	./$(MAIN_OUTPUT)