# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/liubuntu/gopath/src/github.com/libsnark-vnt

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/liubuntu/gopath/src/github.com/libsnark-vnt/build

# Include any dependencies generated for this target.
include depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/depend.make

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/progress.make

# Include the compile flags for this target's objects.
include depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/flags.make

depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o: depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/flags.make
depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o: ../depends/libsnark/libsnark/gadgetlib1/tests/gadgetlib1_test.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/liubuntu/gopath/src/github.com/libsnark-vnt/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o"
	cd /home/liubuntu/gopath/src/github.com/libsnark-vnt/build/depends/libsnark/libsnark && /usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o -c /home/liubuntu/gopath/src/github.com/libsnark-vnt/depends/libsnark/libsnark/gadgetlib1/tests/gadgetlib1_test.cpp

depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.i"
	cd /home/liubuntu/gopath/src/github.com/libsnark-vnt/build/depends/libsnark/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/liubuntu/gopath/src/github.com/libsnark-vnt/depends/libsnark/libsnark/gadgetlib1/tests/gadgetlib1_test.cpp > CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.i

depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.s"
	cd /home/liubuntu/gopath/src/github.com/libsnark-vnt/build/depends/libsnark/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/liubuntu/gopath/src/github.com/libsnark-vnt/depends/libsnark/libsnark/gadgetlib1/tests/gadgetlib1_test.cpp -o CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.s

depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o.requires:

.PHONY : depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o.requires

depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o.provides: depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o.requires
	$(MAKE) -f depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/build.make depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o.provides.build
.PHONY : depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o.provides

depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o.provides.build: depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o


# Object files for target gadgetlib1_simple_test
gadgetlib1_simple_test_OBJECTS = \
"CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o"

# External object files for target gadgetlib1_simple_test
gadgetlib1_simple_test_EXTERNAL_OBJECTS =

depends/libsnark/libsnark/gadgetlib1_simple_test: depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o
depends/libsnark/libsnark/gadgetlib1_simple_test: depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/build.make
depends/libsnark/libsnark/gadgetlib1_simple_test: depends/libsnark/libsnark/libsnark.so
depends/libsnark/libsnark/gadgetlib1_simple_test: depends/libsnark/depends/gtest/googlemock/gtest/libgtest_main.a
depends/libsnark/libsnark/gadgetlib1_simple_test: depends/libsnark/depends/libff/libff/libff.so
depends/libsnark/libsnark/gadgetlib1_simple_test: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/gadgetlib1_simple_test: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/gadgetlib1_simple_test: /usr/lib/x86_64-linux-gnu/libgmpxx.so
depends/libsnark/libsnark/gadgetlib1_simple_test: depends/libsnark/depends/gtest/googlemock/gtest/libgtest.a
depends/libsnark/libsnark/gadgetlib1_simple_test: depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/liubuntu/gopath/src/github.com/libsnark-vnt/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable gadgetlib1_simple_test"
	cd /home/liubuntu/gopath/src/github.com/libsnark-vnt/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/gadgetlib1_simple_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/build: depends/libsnark/libsnark/gadgetlib1_simple_test

.PHONY : depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/build

depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/requires: depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/gadgetlib1/tests/gadgetlib1_test.cpp.o.requires

.PHONY : depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/requires

depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/clean:
	cd /home/liubuntu/gopath/src/github.com/libsnark-vnt/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/gadgetlib1_simple_test.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/clean

depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/depend:
	cd /home/liubuntu/gopath/src/github.com/libsnark-vnt/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/liubuntu/gopath/src/github.com/libsnark-vnt /home/liubuntu/gopath/src/github.com/libsnark-vnt/depends/libsnark/libsnark /home/liubuntu/gopath/src/github.com/libsnark-vnt/build /home/liubuntu/gopath/src/github.com/libsnark-vnt/build/depends/libsnark/libsnark /home/liubuntu/gopath/src/github.com/libsnark-vnt/build/depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/gadgetlib1_simple_test.dir/depend

