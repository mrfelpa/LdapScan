# Dependencies

- The script requires the following dependencies:


    Python 3

    python-ldap
    

- It can be installed using the following command:

`pip install python-ldap`


# Installation

- Download the ***ldapscan.py file.***


# Usage

- To run the Script, use the following command:

`python ldapscan.py [out] [--host HOST] [--port PORT] [--host-file HOST_FILE]`


      -out: The output directory where the script will store the results. This directory will be created if it doesn't exist.

      --host HOST (optional): The host to scan. If not provided, the script will read the hosts from the --host-file argument.

      --port PORT (optional): The port on which the LDAP server is listening. Default is set to 389.

      --host-file HOST_FILE (optional): The path to a file containing a list of hosts to scan in the format host:port. If not provided, the --host argument must be used.
      

# Possible Errors and Troubleshooting



- ***ModuleNotFoundError: No module named 'ldap':*** This error occurs when the python-ldap module is not installed. Make sure you have installed the python-ldap module using the command mentioned in the "Dependencies" section.


- ***ldap.SERVER_DOWN:*** This error indicates that the LDAP server is not accessible or is down. Check the host and port configuration and ensure that the ***LDAP server is running and reachable.***


- ***ldap.TIMEOUT:*** This error occurs when the LDAP server does not respond within the specified timeout period. You can try increasing the timeout value using the --timeout argument when running the script.


- ***ldap.INSUFFICIENT_ACCESS:*** This error indicates that the null bind is not allowed on the ***LDAP server.*** The script requires null bind access to perform the necessary tests. Ensure that the LDAP server allows null bind access or provide valid credentials ***using the --bind-dn and --bind-password arguments when running the script.***


# Disclaimer

Use this script responsibly and ensure that you have proper authorization and consent before performing any security testing.
