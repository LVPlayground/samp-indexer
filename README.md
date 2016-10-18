# SA-MP Server Indexer
A tool to index activity on San Andreas: Multiplayer servers.

## Usage
The indexer has to be used from the command line.

```
samp-indexer -v --server-list test/server_list
```

This will output information from the indexed servers to the console. The following command line
options are available.

  - **--logstash**: Path to the logstash UNIX pipe. _Optional._
  - **--quiet**: Block all output of the tool in its entirety. _Optional._
  - **--retries**: Number of retries for servers that timed out. _Optional._
  - **--server-list**: Path or HTTP URL to the list of servers to index. _Required._
  - **--threads**, **-t**: Number of threads to use. Defaults to the CPU's thread count. _Optional_.
  - **-v**: Enable verbose output. Value should be 0-2. _Optional._
  - **--user-agent**: User agent to send when requesting the server index from an HTTP URL.
