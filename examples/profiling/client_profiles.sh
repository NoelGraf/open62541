#!/bin/bash

# Check if a path was passed as argument
if [ $# -ne 3 ]; then
  echo "Usage: $0 <Path to the executable files> <Client Profile> <Number of Clients>"
  exit 1
fi

# Extract the path to the executable file
executable_path="$1"
profile="$2"
numOfClients="$3"
client="client_profile_default"

# Check if the file exists and is executable
if [ ! -x "$executable_path/$client" ]; then
  echo "The file $executable_path/$client does not exist or is not executable."
  exit 1
fi

# Start the client in profile
for ((i = 1; i <= numOfClients; i++)); do
  if [ "$profile" -eq 1 ]; then
    echo "You entered profile 1."
    "$executable_path/$client" -n 10 -s 1 -m 5 -t 10 &
  elif [ "$profile" -eq 2 ]; then
    echo "You entered profile 2."
    "$executable_path/$client" -n 50 -s 1 -m 10 -t 10 &
  elif [ "$profile" -eq 3 ]; then
    echo "You entered profile 3."
    "$executable_path/$client" -n 100 -s 10 -m 10 -t 10 --cert /home/noel/Dokumente/Arbeit/Fraunhofer/Repo/noel/open62541/tools/certs/client_cert.der --key /home/noel/Dokumente/Arbeit/Fraunhofer/Repo/noel/open62541/tools/certs/client_key.der --securityMode 3 --securityPolicy http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256 &
  elif [ "$profile" -eq 4 ]; then
    echo "You entered profile 4."
    "$executable_path/$client" -n 1000 -s 10 -m 10 -t 10 --cert /home/noel/Dokumente/Arbeit/Fraunhofer/Repo/noel/open62541/tools/certs/client_cert.der --key /home/noel/Dokumente/Arbeit/Fraunhofer/Repo/noel/open62541/tools/certs/client_key.der --securityMode 3 --securityPolicy http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256 &
  else
    echo "Invalid profile. Please enter 1, 2, 3 or 4."
  fi
done

exit 0
