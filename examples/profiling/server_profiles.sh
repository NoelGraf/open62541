#!/bin/bash

run_normal() {
  if [ "$profile" -eq 1 ]; then
    echo "You entered profile 1."
    "$executable_path/$server" -n 10 -l 3 -t 5
  elif [ "$profile" -eq 2 ]; then
    echo "You entered profile 2."
    "$executable_path/$server" -n 10 -l 3 -t 5 --encryption
  elif [ "$profile" -eq 3 ]; then
    echo "You entered profile 3."
    "$executable_path/$server" -n 100 -l 10 -t 5 --encryption
  elif [ "$profile" -eq 4 ]; then
    echo "You entered profile 4."
    "$executable_path/$server" -n 1000 -l 100 -t 5 --encryption
  else
    echo "Invalid profile. Please enter 1, 2, 3 or 4."
  fi
}

run_valgrind() {
  if [ "$profile" -eq 1 ]; then
    echo "You entered profile 1."
    valgrind --tool=massif "$executable_path/$server" -n 10 -l 3 -t 5
  elif [ "$profile" -eq 2 ]; then
    echo "You entered profile 2."
    valgrind --tool=massif "$executable_path/$server" -n 10 -l 3 -t 5 --encryption
  elif [ "$profile" -eq 3 ]; then
    echo "You entered profile 3."
    valgrind --tool=massif "$executable_path/$server" -n 100 -l 10 -t 5 --encryption
  elif [ "$profile" -eq 4 ]; then
    echo "You entered profile 4."
    valgrind --tool=massif "$executable_path/$server" -n 1000 -l 100 -t 5 --encryption
  else
    echo "Invalid profile. Please enter 1, 2, 3 or 4."
  fi
}

run_perf() {
  perf probe -x /lib64/libc.so.6 malloc
  if [ "$profile" -eq 1 ]; then
    echo "You entered profile 1."
    valgrind --tool=massif "$executable_path/$server" -n 10 -l 3 -t 5
  elif [ "$profile" -eq 2 ]; then
    echo "You entered profile 2."
    valgrind --tool=massif "$executable_path/$server" -n 10 -l 3 -t 5 --encryption
  elif [ "$profile" -eq 3 ]; then
    echo "You entered profile 3."
    valgrind --tool=massif "$executable_path/$server" -n 100 -l 10 -t 5 --encryption
  elif [ "$profile" -eq 4 ]; then
    echo "You entered profile 4."
    valgrind --tool=massif "$executable_path/$server" -n 1000 -l 100 -t 5 --encryption
  else
    echo "Invalid profile. Please enter 1, 2, 3 or 4."
  fi
}

# Check if a path was passed as argument
if [ $# -ne 3 ]; then
  echo "Usage: $0 <Path to the executable files> <Server Profile> <Profiling Mode [0=normal, 1=valgrind massif, 2=perf]>"
  exit 1
fi

# Extract the path to the executable file
executable_path="$1"
profile="$2"
mode="$3"
server="server_profile_default"

# Check if the file exists and is executable
if [ ! -x "$executable_path/$server" ]; then
  echo "The file $executable_path/$server does not exist or is not executable."
  exit 1
fi

# Start the server in profile
#valgrind --tool=massif "$executable_path/$server" -n 10 -l 3 -t 5

if [ "$mode" -eq 0 ]; then
  echo "You entered mode normal."
  run_normal
elif [ "$mode" -eq 1 ]; then
  echo "You entered mode valgrind-massif."
  run_valgrind
elif [ "$mode" -eq 2 ]; then
  echo "You entered profile perf."
  run_perf
else
  echo "Invalid mode. Please enter 0, 1 or 2."
fi

exit 0
