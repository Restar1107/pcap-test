# Compiler settings
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra

# Target executable
TARGET = test

# Source files and object files
SRC = main.cpp
OBJ = $(SRC:.cpp=.o)

# Phony targets (these targets are not actual files)
.PHONY: all clean

# Default target
all: $(TARGET)

# Linking step
$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@

# Compilation step
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up object and executable files
clean:
	rm -f $(OBJ) $(TARGET)

