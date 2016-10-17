// Copyright 2016 Las Venturas Playground. All rights reserved.
// Use of this source code is governed by the MIT license, a copy of which can
// be found in the LICENSE file.

#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/thread.hpp>

namespace {

// Options for the indexer. Sets default values. May be overridden by using the command line flags
// listed next to each option. {@see ParseCommandLine}
struct IndexOptions {
  IndexOptions()
      : threads(boost::thread::hardware_concurrency()),
        user_agent("SAMPIndexer/1.0 (+https://sa-mp.nl/)") {}

  ~IndexOptions() = default;

  std::string logstash;     // --logstash
  std::string server_list;  // --server-list
  uint32_t threads;         // --threads, -t
  std::string user_agent;   // --user-agent

  bool output = true;       // Whether to output the results to stdout.
  bool verbose = false;     // Whether to output exactly what's happening.
};

// Definition for a server entry, which exists of an IP address and a port number.
using ServerEntry = std::pair<std::string, uint16_t>;

// Structure containing the information that can be queried from the server.
struct ServerInfo {
  explicit ServerInfo(const ServerEntry& server)
      : server(server) {}

  ServerEntry server;

  bool has_password = false;

  uint16_t players = 0;
  uint16_t max_players = 0;

  std::string hostname;
  std::string gamemode;
  std::string map;
};

// Queue and vector used for processing the identified ServerEntries.
std::queue<ServerEntry> server_queue;

std::vector<ServerEntry> failure_vector;
std::vector<ServerInfo> result_vector;

// Mutexes that protect the aforementioned queue and vector.
std::mutex server_queue_mutex, result_mutex;

// Parses the command line arguments (|argc| and |argv|) in to the IndexOptions (|options|).
bool ParseCommandLine(IndexOptions* options, int argc, const char** argv) {
  namespace po = boost::program_options;

  po::options_description indexer("SA-MP Indexer");
  indexer.add_options()
      ("logstash", po::value<std::string>(), "Path to the logstash UNIX pipe (instead of STDOUT)")
      ("server-list", po::value<std::string>()->required(), "URL of the server list to use")
      ("threads,t", po::value<uint32_t>(), "Number of threads to use")
      ("verbose,v", "Enable verbose output")
      ("user-agent", po::value<std::string>(), "The user agent to use in the request");

  po::variables_map variables;
  try {
    po::store(po::parse_command_line(argc, argv, indexer), variables);
    po::notify(variables);

  } catch (po::error& error) {
    std::cerr << "Unable to parse the command line: " << error.what() << std::endl << std::endl;
    std::cerr << indexer << std::endl;
    return false;
  }

  if (variables.count("logstash")) {
    options->logstash = variables["logstash"].as<std::string>();
    options->output = false;
  }

  if (variables.count("server-list"))
    options->server_list = variables["server-list"].as<std::string>();
  if (variables.count("threads"))
    options->threads = variables["threads"].as<uint32_t>();
  if (variables.count("verbose"))
    options->verbose = true;
  if (variables.count("user-agent"))
    options->user_agent = variables["user-agent"].as<std::string>();

  return true;
}

// Fetches and parses a list of servers from the specified |options.server_list|. Synchronous.
// Supports HTTP (non-HTTPS) URLs, as well as file paths relative to the CHDIR.
bool FetchServerList(std::queue<ServerEntry>* servers, const IndexOptions& options) {
  const std::string& server_list = options.server_list;

  std::vector<std::string> raw_servers;

  if (server_list.substr(0, 7) == "http://") {
    size_t path_separator = server_list.find_first_of('/', 7 /* after the http:// prefix */);
    if (path_separator == std::string::npos) {
      std::cerr << "Invalid hostname given: " << server_list;
      return false;
    }

    using boost::asio::ip::tcp;

    boost::asio::io_service io_service;

    std::string hostname = server_list.substr(7, path_separator - 7);
    std::string path = server_list.substr(path_separator);

    try {
      // (1) Resolve the |hostname| to the IP address associated with it.
      tcp::resolver resolver(io_service);
      tcp::resolver::query query(hostname, "http");
      tcp::resolver::iterator endpoints = resolver.resolve(query);

      // (2) Establish a connection to one of the |endpoints|.
      tcp::socket socket(io_service);
      boost::asio::connect(socket, endpoints);

      boost::asio::streambuf request;
      boost::asio::streambuf response;

      // (3) Build the request headers for the server list.
      std::ostream request_stream(&request);

      request_stream << "GET " << path << " HTTP/1.0\r\n";
      request_stream << "Host: " << hostname << "\r\n";
      request_stream << "User-Agent: " << options.user_agent << "\r\n";
      request_stream << "Connection: close\r\n\r\n";

      boost::asio::write(socket, request);

      std::string http_version;
      uint32_t http_status_code;

      // (4) Read the response received from the server and make that it's OK.
      boost::asio::read_until(socket, response, "\r\n");

      std::istream response_stream(&response);

      response_stream >> http_version;
      response_stream >> http_status_code;
      
      if (!response_stream || http_version.substr(0, 5) != "HTTP/" || http_status_code != 200) {
        std::cerr << "Received an invalid HTTP response (" << http_version << "; "
                  << http_status_code << ")" << std::endl;
        return false;
      }

      boost::system::error_code error;

      // (5) Make sure that we've read the entire response in the |response| stream.
      while (boost::asio::read(socket, response, boost::asio::transfer_at_least(1), error)) {}

      if (error != boost::asio::error::eof)
        throw boost::system::system_error(error);

      // (6) Skip over the headers included in the |response|.
      for (std::string header; std::getline(response_stream, header) && header != "\r";) {}

      // (7) Interpret the rest of the lines as server definitions.
      for (std::string line; std::getline(response_stream, line);)
        raw_servers.push_back(line);

      socket.close();
    }
    catch (std::exception& e) {
      std::cerr << "Unable to fetch the server list: " << e.what() << std::endl;
      return false;
    }
  } else {
    std::ifstream file(server_list, std::ifstream::in);
    if (file.is_open()) {
      for (std::string line; std::getline(file, line);)
        raw_servers.push_back(line);

      file.close();
    }
  }

  if (!raw_servers.size()) {
    std::cerr << "Unable to load the list of servers from: " << server_list;
    return false;
  }

  for (const std::string& input_line : raw_servers) {
    std::string line = boost::trim_copy(input_line);

    size_t colon_position = line.find_first_of(':');
    if (colon_position == std::string::npos) {
      std::cerr << "Unable to parse server entry: " << line;
      continue;
    }

    uint16_t port_number;
    try {
      port_number = boost::lexical_cast<uint16_t>(line.substr(colon_position + 1));
    } catch (boost::bad_lexical_cast const&) {
      std::cerr << "Invalid port number for server entry: " << line;
      continue;
    }

    servers->emplace(line.substr(0, colon_position), port_number);
  }

  return true;
}

// Queries the server defined in |info|. Writes the results to |info| as well.
bool QueryServer(ServerInfo* info) {
  // TODO: Actually query the server defined in |info|.
  return false;
}

// Thread responsible for querying servers. It will pick a ServerEntry from the vector of parsed
// server entries, query it, and then write the results to the vector of queried servers. Both
// vectors are protected by mutexes
void QueryThread() {
  ServerEntry server;

  while (true) {
    {
      std::lock_guard<std::mutex> guard(server_queue_mutex);
      if (server_queue.empty())
        return;

      server = server_queue.front();
      server_queue.pop();
    }

    ServerInfo info(server);

    const bool success = QueryServer(&info);
    {
      std::lock_guard<std::mutex> guard(result_mutex);
      if (success)
        result_vector.push_back(std::move(info));
      else
        failure_vector.push_back(server);
    }
  }
}

}  // namespace

int main(int argc, const char** argv) {
  IndexOptions options;
  if (!ParseCommandLine(&options, argc, argv))
    return 1;

  if (options.verbose)
    std::cout << "Parsing servers from '" << options.server_list << "'..." << std::endl;

  if (!FetchServerList(&server_queue, options))
    return 1;

  if (options.verbose)
    std::cout << "Found " << server_queue.size() << " servers..." << std::endl;

  if (!server_queue.size())
    return 0;  // there are no servers to index

  // Now query all servers in the list in parallel, using |options.threads| threads.
  {
    boost::thread_group query_threads;
    for (size_t i = 0; i < options.threads; ++i)
      query_threads.create_thread(QueryThread);

    query_threads.join_all();
  }

  // TODO: Write the results to `logstash` when this has been configured.
  for (const ServerInfo& info : result_vector)
    std::cout << info.server.first << ":" << info.server.second << " -- " << info.players << " players";

  for (const ServerEntry& server : failure_vector)
    std::cout << "Unable to query " << server.first << ":" << server.second << std::endl;

  return 0;
}
