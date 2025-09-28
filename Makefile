INPUT = source/mutate.cpp
OUTPUT = output/mutate

all:
	g++ -mrdseed -lssl -lcrypto -O3 -Wall -Wextra -o $(OUTPUT) $(INPUT)

clean:
	rm -f $(OUTPUT)

run: $(MAIN_OUTPUT)
	./$(OUTPUT)

dbg: $(MAIN_OUTPUT)
	gdb $(OUTPUT)
