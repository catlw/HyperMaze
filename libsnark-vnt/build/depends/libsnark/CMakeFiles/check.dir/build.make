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

# Utility rule file for check.

# Include the progress variables for this target.
include depends/libsnark/CMakeFiles/check.dir/progress.make

depends/libsnark/CMakeFiles/check:
	cd /home/liubuntu/gopath/src/github.com/libsnark-vnt/build/depends/libsnark && /usr/bin/ctest

check: depends/libsnark/CMakeFiles/check
check: depends/libsnark/CMakeFiles/check.dir/build.make

.PHONY : check

# Rule to build all files generated by this target.
depends/libsnark/CMakeFiles/check.dir/build: check

.PHONY : depends/libsnark/CMakeFiles/check.dir/build

depends/libsnark/CMakeFiles/check.dir/clean:
	cd /home/liubuntu/gopath/src/github.com/libsnark-vnt/build/depends/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/check.dir/cmake_clean.cmake
.PHONY : depends/libsnark/CMakeFiles/check.dir/clean

depends/libsnark/CMakeFiles/check.dir/depend:
	cd /home/liubuntu/gopath/src/github.com/libsnark-vnt/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/liubuntu/gopath/src/github.com/libsnark-vnt /home/liubuntu/gopath/src/github.com/libsnark-vnt/depends/libsnark /home/liubuntu/gopath/src/github.com/libsnark-vnt/build /home/liubuntu/gopath/src/github.com/libsnark-vnt/build/depends/libsnark /home/liubuntu/gopath/src/github.com/libsnark-vnt/build/depends/libsnark/CMakeFiles/check.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/CMakeFiles/check.dir/depend

