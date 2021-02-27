
For library Libcli: 
	- Download https://github.com/dparrish/libcli
	- $ make
	  $ sudo make install

- To compile:
	- $ export LD_LIBRARY_PATH=/usr/local/lib
	- $ gcc  myFileSystemMonitor.c  -lpthread -lcli -finstrument-functions  -rdynamic  -o main
	- $ sudo chmod 777 /var/www/html/index.html

- To execute:
	- $./main -d /[directory] -i 127.0.0.1

Listen to UDP server:
	- $netcat -l -u -p 5000

Run CLI for backtrace:
	- $telnet localhost 8000

For telnet:
User: user
Password: 111111