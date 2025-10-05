INPUT = source/mutate.cpp
OUTPUT = output/mutate

all: $(OUTPUT)

$(OUTPUT):
	mkdir -p output
	g++ -g -mrdseed -O3 -Wall -Wextra -o $(OUTPUT) $(INPUT) -lssl -lcrypto

clean:
	rm -f $(OUTPUT)
