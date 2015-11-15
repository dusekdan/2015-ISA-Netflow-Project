all:
	g++ -std=c++11  isa_exporter.cpp -o  isa_exporter -lpcap
	g++ -std=c++11 isaexp.cpp -o isaexp -lpcap

clean:
	rm isa_exporter
	rm isaexp