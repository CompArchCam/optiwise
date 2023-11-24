CXXFLAGS = -std=c++11 -O3 -Wall -g

ifndef SERIAL
OMP = -fopenmp
else
OMP = -DSERIAL
endif

SRC = loop_profiler.cpp loop_fetcher.cpp io.cpp
EXE = analyzer

all: $(EXE)

clean:
	rm -f $(EXE)

$(EXE): $(SRC) *.hpp
	$(CXX) $(CXXFLAGS) $(OMP) $(CPPFLAGS) -o $(EXE) $(SRC)
