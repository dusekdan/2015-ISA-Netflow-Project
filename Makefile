all:
	g++ isa_exporter.cpp -o isa_exporter -lpcap

clean:
	rm isa_exporter