// Copyright 2016 Las Venturas Playground. All rights reserved.
// Use of this source code is governed by the MIT license, a copy of which can
// be found in the LICENSE file.

#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/thread.hpp>

#if defined(WIN32)
#include <Windows.h>
#elif defined(LINUX)
#include <sys/time.h>
#include <time.h>
#endif

namespace {

// Verbosity setting for the indexer.
enum class Verbosity {
  QUIET,
  DEFAULT,
  VERBOSE,
  DEBUG
};

// Options for the indexer. Sets default values. May be overridden by using the command line flags
// listed next to each option. {@see ParseCommandLine}
struct IndexOptions {
  IndexOptions()
      : threads(boost::thread::hardware_concurrency()),
        timeout(4 /* seconds */),
        user_agent("SAMPIndexer/1.0 (+https://sa-mp.nl/)") {}

  ~IndexOptions() = default;

  std::string logstash;     // --logstash
  std::string server_list;  // --server-list
  uint32_t threads;         // --threads, -t
  uint32_t timeout;         // --timeout
  std::string user_agent;   // --user-agent

  Verbosity verbosity = Verbosity::DEBUG;  // -v, -quiet
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

// -------------------------------------------------------------------------------------------------

IndexOptions options;

// Queue and vector used for processing the identified ServerEntries.
std::queue<ServerEntry> server_queue;

std::vector<ServerEntry> failure_vector;
std::vector<ServerInfo> result_vector;

// Mutexes that protect the aforementioned queue and vector, as well as verbose output.
std::mutex server_queue_mutex, result_mutex, verbose_output_mutex;

// -------------------------------------------------------------------------------------------------

std::string ToDisplay(const ServerEntry& server) {
  return server.first + ":" + std::to_string(server.second);
}

// -------------------------------------------------------------------------------------------------

#if defined(WIN32)

// Difference between January 1st, 1601 and January 1st, 1970 in nanoseconds, to convert from
// the Windows file time epoch to the UNIX timestamp epoch.
const uint64_t kEpochDelta = 116444736000000000ull;

double monotonicallyIncreasingTime() {
  static uint64_t begin_time = 0ull;
  static bool set_begin_time = false;

  FILETIME tm;

  // Use precise (<1us) timing for Windows 8 and above, normal (~1ms) on other versions.
#if defined(NTDDI_WIN8) && NTDDI_VERSION >= NTDDI_WIN8
  GetSystemTimePreciseAsFileTime(&tm);
#else
  GetSystemTimeAsFileTime(&tm);
#endif

  uint64_t time = 0;
  time |= tm.dwHighDateTime;
  time <<= 32;
  time |= tm.dwLowDateTime;
  time -= kEpochDelta;

  if (!set_begin_time) {
    set_begin_time = true;
    begin_time = time;
  }

  return static_cast<double>(time - begin_time) / 10000.0;
}

#elif defined(LINUX)

double monotonicallyIncreasingTime() {
  static uint64_t begin_time = 0ull;
  static bool set_begin_time = false;

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);

  uint64_t time = static_cast<uint64_t>(ts.tv_sec) * 1000000000u + static_cast<uint64_t>(ts.tv_nsec);

  if (!set_begin_time) {
    set_begin_time = true;
    begin_time = time;
  }

  return static_cast<double>(time - begin_time) / 1000000.0;
}

#endif

// -------------------------------------------------------------------------------------------------

// Parses the command line arguments (|argc| and |argv|) in to the IndexOptions (|options|).
bool ParseCommandLine(IndexOptions* options, int argc, const char** argv) {
  namespace po = boost::program_options;

  uint32_t verbosity = 0;

  po::options_description indexer("SA-MP Indexer");
  indexer.add_options()
      ("logstash", po::value<std::string>(), "Path to the logstash UNIX pipe (instead of STDOUT)")
      ("quiet,q", "Block all output")
      ("server-list", po::value<std::string>()->required(), "URL of the server list to use")
      ("threads,t", po::value<uint32_t>(), "Number of threads to use")
      ("timeout", po::value<uint32_t>(), "Request timeout for an individual server, in seconds")
      ("user-agent", po::value<std::string>(), "The user agent to use in the request")
      (",v", po::value<uint32_t>(&verbosity)->implicit_value(0), "Enable verbose output");

  po::variables_map variables;
  try {
    po::store(po::parse_command_line(argc, argv, indexer), variables);
    po::notify(variables);

  } catch (po::error& error) {
    std::cerr << "Unable to parse the command line: " << error.what() << std::endl << std::endl;
    std::cerr << indexer << std::endl;
    return false;
  }

  if (variables.count("logstash"))
    options->logstash = variables["logstash"].as<std::string>();

  if (variables.count("server-list"))
    options->server_list = variables["server-list"].as<std::string>();
  if (variables.count("threads"))
    options->threads = variables["threads"].as<uint32_t>();
  if (variables.count("user-agent"))
    options->user_agent = variables["user-agent"].as<std::string>();

  options->verbosity = Verbosity::DEFAULT;

  if (verbosity == 1)
    options->verbosity = Verbosity::VERBOSE;
  else if (verbosity >= 2)
    options->verbosity = Verbosity::DEBUG;
  else if (variables.count("quiet"))
    options->verbosity = Verbosity::QUIET;

  return true;
}

// Fetches and parses a list of servers from the specified |options.server_list|. Synchronous.
// Supports HTTP (non-HTTPS) URLs, as well as file paths relative to the CHDIR.
bool FetchServerList(std::queue<ServerEntry>* servers) {
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
        if (options.verbosity != Verbosity::QUIET) {
          std::cerr << "Received an invalid HTTP response (" << http_version << "; "
                    << http_status_code << ")" << std::endl;
        }

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
      if (options.verbosity != Verbosity::QUIET) {
        std::cerr << "Unable to fetch the server list: " << e.what() << std::endl;
      }

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
    if (options.verbosity != Verbosity::QUIET) {
      std::cerr << "Unable to load the list of servers from: " << server_list;
    }

    return false;
  }

  for (const std::string& input_line : raw_servers) {
    std::string line = boost::trim_copy(input_line);

    size_t colon_position = line.find_first_of(':');
    if (colon_position == std::string::npos) {
      if (options.verbosity != Verbosity::QUIET) {
        std::cerr << "Unable to parse server entry: " << line;
      }

      continue;
    }

    uint16_t port_number;
    try {
      port_number = boost::lexical_cast<uint16_t>(line.substr(colon_position + 1));
    } catch (boost::bad_lexical_cast const&) {
      if (options.verbosity != Verbosity::QUIET) {
        std::cerr << "Invalid port number for server entry: " << line;
      }

      continue;
    }

    servers->emplace(line.substr(0, colon_position), port_number);
  }

  return true;
}

// -------------------------------------------------------------------------------------------------

template <typename T>
bool ReadValue(T* storage, const boost::array<char, 256>& buffer, const size_t& bytes, size_t* offset) {
  throw std::runtime_error("Invalid ReadValue() overload reached.");
}

template <>
bool ReadValue(bool* storage, const boost::array<char, 256>& buffer, const size_t& bytes, size_t* offset) {
  if (*offset + sizeof(bool) > bytes)
    return false;

  *storage = !!buffer[*offset];
  *offset += sizeof(bool);

  return true;
}

template <>
bool ReadValue(uint16_t* storage, const boost::array<char, 256>& buffer, const size_t& bytes, size_t* offset) {
  if (*offset + sizeof(uint16_t) > bytes)
    return false;

  *storage = static_cast<unsigned char>(buffer[*offset]) |
             static_cast<unsigned char>(buffer[*offset + 1]) << 8;

  *offset += sizeof(uint16_t);

  return true;
}

template <>
bool ReadValue(std::string* storage, const boost::array<char, 256>& buffer, const size_t& bytes, size_t* offset) {
  if (*offset + sizeof(uint32_t) > bytes)
    return false;

  uint32_t length = static_cast<unsigned char>(buffer[*offset]) |
                    static_cast<unsigned char>(buffer[*offset + 1]) << 8 |
                    static_cast<unsigned char>(buffer[*offset + 2]) << 16 |
                    static_cast<unsigned char>(buffer[*offset + 3]) << 24;

  *offset += sizeof(uint32_t);

  if (*offset + length > bytes)
    return false;

  *storage = std::string(&buffer[*offset], length);
  *offset += length;

  return true;
}

// -------------------------------------------------------------------------------------------------

// Queries the server defined in |info|. Writes the results to |info| as well.
bool QueryServer(ServerInfo* info, boost::asio::io_service& io_service) {
  unsigned char packet[11];

  boost::asio::ip::address_v4 address = boost::asio::ip::address_v4::from_string(info->server.first);
  unsigned short port = info->server.second;

  // Compile the information in |packet| necessary to query the server.
  {
    packet[0] = 'S';
    packet[1] = 'A';
    packet[2] = 'M';
    packet[3] = 'P';

    auto address_bytes = address.to_bytes();

    packet[4] = address_bytes[0];
    packet[5] = address_bytes[1];
    packet[6] = address_bytes[2];
    packet[7] = address_bytes[3];

    packet[8] = info->server.second & 0xFF;
    packet[9] = (info->server.second >> 8) & 0xFF;

    packet[10] = 'i';  // information packet identifier
  }

  using boost::asio::ip::udp;
  try {
    udp::endpoint endpoint;
    endpoint.address(address);
    endpoint.port(port);

    udp::socket socket(io_service);

    socket.open(endpoint.protocol());

#if defined(WIN32)
    uint32_t timeout = options.timeout * 1000;
    setsockopt(socket.native(), SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(socket.native(), SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = options.timeout;
    tv.tv_usec = 0;

    setsockopt(socket.native(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(socket.native(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    boost::array<char, 256> receive_buffer;

    // Send the |packet| to the |endpoint| over the opened |socket|.
    if (socket.send_to(boost::asio::buffer(packet), endpoint) != sizeof(packet))
      return false;

    size_t bytes = socket.receive_from(boost::asio::buffer(receive_buffer), endpoint);
    size_t offset = 11;  // the |packet| that we sent

    if (bytes <= offset)
      throw std::runtime_error("Received packet size too short");

    return ReadValue(&info->has_password, receive_buffer, bytes, &offset) &&
           ReadValue(&info->players, receive_buffer, bytes, &offset) &&
           ReadValue(&info->max_players, receive_buffer, bytes, &offset) &&
           ReadValue(&info->hostname, receive_buffer, bytes, &offset) &&
           ReadValue(&info->gamemode, receive_buffer, bytes, &offset) &&
           ReadValue(&info->map, receive_buffer, bytes, &offset);

  } catch (std::exception& e) {
    if (options.verbosity == Verbosity::VERBOSE || options.verbosity == Verbosity::DEBUG) {
      std::lock_guard<std::mutex> guard(verbose_output_mutex);
      std::cerr << "[" << ToDisplay(info->server) << "] ERROR: " << e.what() << std::endl;
    }
    return false;
  }

  return true;
}

// Thread responsible for querying servers. It will pick a ServerEntry from the vector of parsed
// server entries, query it, and then write the results to the vector of queried servers. Both
// vectors are protected by mutexes
void QueryThread() {
  boost::asio::io_service io_service;
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

    double begin = 0;

    if (options.verbosity == Verbosity::DEBUG) {
      begin = monotonicallyIncreasingTime();

      std::lock_guard<std::mutex> guard(verbose_output_mutex);
      std::cout << "[" << ToDisplay(server) << "] Querying the server..." << std::endl;
    }

    const bool success = QueryServer(&info, io_service);

    if (options.verbosity == Verbosity::DEBUG) {
      long int delta = lround(monotonicallyIncreasingTime() - begin);

      std::lock_guard<std::mutex> guard(verbose_output_mutex);
      std::cout << "[" << ToDisplay(server) << "] Finished the query in "
                << std::setprecision(2) << delta << "ms" << std::endl;
    }

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

// -------------------------------------------------------------------------------------------------

int main(int argc, const char** argv) {
  if (!ParseCommandLine(&options, argc, argv))
    return 1;  // unable to parse the command line

  if (options.verbosity == Verbosity::VERBOSE)
    std::cout << "Parsing servers from '" << options.server_list << "'..." << std::endl;

  if (!FetchServerList(&server_queue))
    return 1;  // unable to fetch the list of servers

  if (options.verbosity == Verbosity::VERBOSE)
    std::cout << "Found " << server_queue.size() << " servers..." << std::endl;

  const size_t server_count = server_queue.size();
  if (!server_count)
    return 1;  // unable to find servers to index

  double begin = monotonicallyIncreasingTime();

  // Now query all servers in the list in parallel, using |options.threads| threads.
  {
    boost::thread_group query_threads;
    for (size_t i = 0; i < options.threads; ++i)
      query_threads.create_thread(QueryThread);

    query_threads.join_all();
  }

  long int delta = lround(monotonicallyIncreasingTime() - begin);

  // Output the total time taken for the query sequence when verbose output is enabled.
  if (options.verbosity != Verbosity::QUIET) {
    std::cout << "Queried " << server_count << " servers in " << std::setprecision(2) << delta << "ms." << std::endl;
    std::cout << "Successful: " << result_vector.size() << ". Failed: " << failure_vector.size() << std::endl;

    uint32_t player_count = 0;
    uint32_t player_slot_count = 0;

    for (const ServerInfo& info : result_vector) {
      player_count += info.players;
      player_slot_count += info.max_players;
    }

    std::cout << "There are " << player_count << " players online, with a capacity of " << player_slot_count << "."
              << std::endl << std::endl;
  }

  if (!options.logstash.empty()) {
#if defined(BOOST_ASIO_HAS_LOCAL_SOCKETS)
    boost::asio::io_service logstash_io_service;
    boost::asio::local::stream_protocol::socket logstash_socket(logstash_io_service);

    try {
      logstash_socket.connect(boost::asio::local::stream_protocol::endpoint(options.logstash));

      for (const ServerInfo& info : result_vector) {
        std::stringstream stream;

        stream << "{";
        {
          stream << "\"type\": \"query\",";
          stream << "\"server\": \"" << info.server.first << ":" << info.server.second << "\",";
          stream << "\"online\": 1,";
          stream << "\"players\": " << info.players << ",";
          stream << "\"max_players\": " << info.max_players;
        }
        stream << "}";

        boost::asio::write(logstash_socket, boost::asio::buffer(stream.str()));
      }

      for (const ServerEntry& server : failure_vector) {
        std::stringstream stream;

        stream << "{";
        {
          stream << "\"type\": \"query\",";
          stream << "\"server\": \"" << server.first << ":" << server.second << "\",";
          stream << "\"online\": 0,";
          stream << "\"players\": 0,";
          stream << "\"max_players\": 0";
        }
        stream << "}";

        boost::asio::write(logstash_socket, boost::asio::buffer(stream.str()));
      }

    } catch (std::exception& e) {
      if (options.verbosity != Verbosity::QUIET)
        std::cerr << "LOGSTASH ERROR: " << e.what() << std::endl;
    }
#endif
  }

  if (options.verbosity == Verbosity::DEBUG) {
    for (const ServerInfo& info : result_vector) {
      std::cout << ToDisplay(info.server) << " -- " << info.players << "/" << info.max_players << " -- ";
      std::cout << info.hostname << " (" << info.gamemode << ")" << std::endl;
    }
  }
  
  return 0;  // no errors \o/
}
