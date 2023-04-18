# Nmap

| Option      | Full Command | Description    |
| :---        |    :----:   |          ---: |
| -v     | nmap -v [target]       | Verbose output  |
| -O     | nmap -O [target]       | OS detection   |
| -sS    | nmap -sS [target]      | Fast scan
| -sT    | nmap -sT [target]      | Half-scan, doesn't complete tcp handshake |
| -sU    | nmap -sU [target]      | Full scan, completeds tcp handshake
| -sA    | nmap -sA [target]      | Firewall identification
| -sV    | nmap -sV [target]      | Finds service on each responding port
