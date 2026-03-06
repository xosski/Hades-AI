#ARP commands

#!/bin/bash

echo "ARP Table:"
arp -n

echo ""
echo "IP Configuration:"
ifconfig  # or use 'ip a'

echo ""
echo "Hostname:"
hostname

echo ""
echo "Netstat:"
netstat -tuln

echo ""
echo "NSLookup:"
nslookup example.com

echo ""
echo "Ping:"
ping -c 4 example.com

echo ""
echo "Pathping (not available on Linux, using traceroute):"
traceroute example.com

echo ""
echo "Routing Table:"
route -n

echo ""
echo "Traceroute:"
traceroute example.com

echo ""
echo "Tracepath:"
tracepath example.com

echo ""
echo "Dig:"
dig example.com

#CHARACTER AND BIT STUFFING -------------------------------------------------------------------------------------------------------

#include <iostream>
#include <vector>
#include <string>

using namespace std;

// Function for Character Stuffing
string characterStuffing(const string &data) {
    string stuffedData;
    char flag = '#'; // Using '#' as the frame delimiter
    stuffedData += flag; // Start frame

    for (char c : data) {
        if (c == flag) {
            stuffedData += flag; // Stuff the flag character
        }
        stuffedData += c;
    }

    stuffedData += flag; // End frame
    return stuffedData;
}

// Function for Bit Stuffing
string bitStuffing(const string &data) {
    string stuffedData;
    stuffedData.reserve(data.length() + data.length() / 5); // Reserve space for stuffed bits
    int count = 0;

    for (char c : data) {
        // Convert character to binary string
        for (int i = 7; i >= 0; --i) {
            bool bit = (c >> i) & 1;
            stuffedData += bit ? '1' : '0';
            if (bit) {
                count++;
                // If we have five consecutive 1s, stuff a 0
                if (count == 5) {
                    stuffedData += '0';
                    count = 0; // Reset count after stuffing
                }
            } else {
                count = 0; // Reset count if we encounter a 0
            }
        }
    }
    return stuffedData;
}

// Function to display binary data
void displayBinary(const string &data) {
    for (char c : data) {
        cout << bitset<8>(c) << " "; // Display each character as binary
    }
    cout << endl;
}

int main() {
    string data;

    cout << "Enter the data to be framed: ";
    getline(cin, data);

    // Character Stuffing
    string stuffedDataChar = characterStuffing(data);
    cout << "Character Stuffed Data: " << stuffedDataChar << endl;

    // Bit Stuffing
    string stuffedDataBit = bitStuffing(data);
    cout << "Bit Stuffed Data: ";
    displayBinary(stuffedDataBit);

    return 0;
}

#-------HAMMING CODE --------------------------------------------------------------------------------------------------------

#include <iostream>
#include <vector>
#include <bitset>

using namespace std;

// Function to calculate Hamming Code
string generateHammingCode(const string &data) {
    int m = data.length();
    int r = 0;

    // Calculate the number of parity bits required
    while ((1 << r) < (m + r + 1)) {
        r++;
    }

    string hammingCode(m + r, '0');
    int j = 0, k = 0;

    // Place data bits in the Hamming code
    for (int i = 1; i <= m + r; i++) {
        if (i == (1 << j)) {
            hammingCode[i - 1] = '0'; // Placeholder for parity bits
            j++;
        } else {
            hammingCode[i - 1] = data[k++];
        }
    }

    // Calculate parity bits
    for (int i = 0; i < r; i++) {
        int parityIndex = (1 << i) - 1;
        int count = 0;

        for (int j = 1; j <= m + r; j++) {
            if (j & (1 << i)) {
                if (hammingCode[j - 1] == '1') {
                    count++;
                }
            }
        }

        hammingCode[parityIndex] = (count % 2 == 0) ? '0' : '1';
    }

    return hammingCode;
}

// Function to calculate Normal Checksum
unsigned int normalChecksum(const vector<unsigned int> &data) {
    unsigned int sum = 0;
    for (unsigned int num : data) {
        sum += num;
    }
    return sum; // Truncated to fit the size of the checksum
}

// Function to calculate 1's Complement Checksum
unsigned int onesComplementChecksum(const vector<unsigned int> &data) {
    unsigned int sum = 0;
    for (unsigned int num : data) {
        sum += num;
    }
    return ~sum; // Invert the sum
}

// Function to calculate 2's Complement Checksum
unsigned int twosComplementChecksum(const vector<unsigned int> &data) {
    unsigned int sum = 0;
    for (unsigned int num : data) {
        sum += num;
    }
    return ~sum + 1; // Invert the sum and add 1
}

int main() {
    // Hamming Code Generation
    string data;
    cout << "Enter the data bits (binary): ";
    cin >> data;

    string hammingCode = generateHammingCode(data);
    cout << "Hamming Code: " << hammingCode << endl;

    // Checksum Calculation
    int n;
    cout << "Enter the number of data words for checksum calculation: ";
    cin >> n;

    vector<unsigned int> dataWords(n);
    cout << "Enter the data words (in decimal): ";
    for (int i = 0; i < n; i++) {
        cin >> dataWords[i];
    }

    unsigned int normalSum = normalChecksum(dataWords);
    unsigned int onesComplementSum = onesComplementChecksum(dataWords);
    unsigned int twosComplementSum = twosComplementChecksum(dataWords);

    cout << "Normal Checksum: " << normalSum << endl;
    cout << "1's Complement Checksum: " << onesComplementSum << endl;
    cout << "2's Complement Checksum: " << twosComplementSum << endl;

    return 0;
}

#------- CRC ------------------------------------------------------------------------------------------------------------------------

#include <iostream>
#include <vector>
#include <bitset>

using namespace std;

// Function to perform CRC calculation
unsigned int crc(const string &data, const string &polynomial) {
    // Append zeros to the data
    string paddedData = data + string(polynomial.length() - 1, '0');
    unsigned int poly = bitset<32>(polynomial).to_ulong();
    unsigned int dataBits = bitset<32>(paddedData).to_ulong();
    unsigned int divisor = poly;

    // Perform the division
    for (size_t i = 0; i < data.length(); i++) {
        if ((dataBits >> (data.length() + polynomial.length() - 1 - i)) & 1) {
            dataBits ^= (divisor << (data.length() - 1 - i));
        }
    }

    return dataBits; // Remainder
}

// CRC-12 Polynomial: x^12 + x^11 + x^3 + x^2 + 1 (0x80F)
unsigned int crc12(const string &data) {
    return crc(data, "100000000111"); // CRC-12 polynomial
}

// CRC-16 Polynomial: x^16 + x^15 + x^2 + 1 (0xA001)
unsigned int crc16(const string &data) {
    return crc(data, "10000000000000101"); // CRC-16 polynomial
}

// CRC-CCITT Polynomial: x^16 + x^12 + x^5 + 1 (0x1021)
unsigned int crcCCITT(const string &data) {
    return crc(data, "10001000000100001"); // CRC-CCITT polynomial
}

// CRC-32 Polynomial: x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^3 + x^2 + x + 1 (0xEDB88320)
unsigned int crc32(const string &data) {
    return crc(data, "10011000001000111011001101000000"); // CRC-32 polynomial
}

int main() {
    string data;
    cout << "Enter the data bits (binary): ";
    cin >> data;

    unsigned int crc12Result = crc12(data);
    unsigned int crc16Result = crc16(data);
    unsigned int crcCCITTResult = crcCCITT(data);
    unsigned int crc32Result = crc32(data);

    cout << "CRC-12: " << bitset<12>(crc12Result) << " (Decimal: " << crc12Result << ")" << endl;
    cout << "CRC-16: " << bitset<16>(crc16Result) << " (Decimal: " << crc16Result << ")" << endl;
    cout << "CRC-CCITT: " << bitset<16>(crcCCITTResult) << " (Decimal: " << crcCCITTResult << ")" << endl;
    cout << "CRC-32: " << bitset<32>(crc32Result) << " (Decimal: " << crc32Result << ")" << endl;

    return 0;
}

#--------C++ Program to Display Hostname, IPv4 Address, Class, Network ID, and Host ID-----------------------------------------

#include <iostream>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>

using namespace std;

// Function to get the class of the IP address
char getClass(const string &ip) {
    int firstOctet = stoi(ip.substr(0, ip.find('.')));
    if (firstOctet >= 0 && firstOctet <= 127) return 'A';
    else if (firstOctet >= 128 && firstOctet <= 191) return 'B';
    else if (firstOctet >= 192 && firstOctet <= 223) return 'C';
    else if (firstOctet >= 224 && firstOctet <= 239) return 'D';
    else return 'E';
}

// Function to calculate Network ID and Host ID
void calculateNetworkAndHostID(const string &ip, string &networkID, string &hostID) {
    vector<int> octets;
    size_t pos = 0;
    string token;
    while ((pos = ip.find('.')) != string::npos) {
        token = ip.substr(0, pos);
        octets.push_back(stoi(token));
        ip.erase(0, pos + 1);
    }
    octets.push_back(stoi(ip)); // Last octet

    // Class A, B, C
    if (getClass(ip) == 'A') {
        networkID = to_string(octets[0]) + ".0.0.0";
        hostID = to_string(octets[0]) + ".0.0." + to_string(octets[1]);
    } else if (getClass(ip) == 'B') {
        networkID = to_string(octets[0]) + "." + to_string(octets[1]) + ".0.0";
        hostID = to_string(octets[2]) + "." + to_string(octets[3]);
    } else if (getClass(ip) == 'C') {
        networkID = to_string(octets[0]) + "." + to_string(octets[1]) + "." + to_string(octets[2]) + ".0";
        hostID = to_string(octets[3]);
    }
}

int main() {
    char hostname[1024];
    gethostname(hostname, sizeof(hostname));
    cout << "Hostname: " << hostname << endl;

    struct ifaddrs *ifaddr, *ifa;
    getifaddrs(&ifaddr);
    string ipv4Address;

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ip, sizeof(ip));
            ipv4Address = ip;
            break; // Get the first IPv4 address
        }
    }
    freeifaddrs(ifaddr);

    cout << "IPv4 Address: " << ipv4Address << endl;
    cout << "Class: " << getClass(ipv4Address) << endl;

    string networkID, hostID;
    calculateNetworkAndHostID(ipv4Address, networkID, hostID);
    cout << "Network ID: " << networkID << endl;
    cout << "Host ID: " << hostID << endl;

    return 0;
}

#-----------Dotted Decimal IPv4 Address to 32-bit-----------------------------------------------------------------------------------

#include <iostream>
#include <string>
#include <bitset>
#include <sstream>
#include <vector>

using namespace std;

// Function to validate the IPv4 address
bool isValidIPv4(const string &ip) {
    stringstream ss(ip);
    string octet;
    int octetCount = 0;

    while (getline(ss, octet, '.')) {
        if (octetCount >= 4) return false; // More than 4 octets
        if (octet.empty() || octet.length() > 3) return false; // Empty or too long
        for (char c : octet) {
            if (!isdigit(c)) return false; // Non-digit character
        }
        int num = stoi(octet);
        if (num < 0 || num > 255) return false; // Out of range
        octetCount++;
    }
    return octetCount == 4; // Must have exactly 4 octets
}

// Function to convert dotted decimal IP to 32-bit binary
string convertTo32Bit(const string &ip) {
    string binaryIP;
    stringstream ss(ip);
    string octet;

    while (getline(ss, octet, '.')) {
        int num = stoi(octet);
        binaryIP += bitset<8>(num).to_string(); // Convert each octet to binary
    }

    return binaryIP; // Return the full 32-bit binary representation
}

int main() {
    string ipAddress;

    cout << "Enter a valid IPv4 address (dotted decimal format): ";
    cin >> ipAddress;

    // Validate the IPv4 address
    if (!isValidIPv4(ipAddress)) {
        cout << "Invalid IPv4 address format." << endl;
        return 1;
    }

    // Convert to 32-bit binary representation
    string binaryRepresentation = convertTo32Bit(ipAddress);

    // Display the result
    cout << "32-bit binary representation: " << binaryRepresentation << endl;

    return 0;
}

#-------ECHO server----------------------------------------------------------------------------------------------------------------

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

using namespace std;

#define PORT 8080 // Port number for the server

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Attach socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET; // IPv4
    address.sin_addr.s_addr = INADDR_ANY; // Bind to any address
    address.sin_port = htons(PORT); // Port

    // Bind the socket to the address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen");
        exit(EXIT_FAILURE);
    }

    cout << "ECHO server is listening on port " << PORT << endl;

    // Accept a connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("Accept");
        exit(EXIT_FAILURE);
    }

    // Echo back messages
    while (true) {
        int valread = read(new_socket, buffer, 1024);
        if (valread <= 0) {
            cout << "Client disconnected." << endl;
            break;
        }
        cout << "Received: " << buffer << endl;
        send(new_socket, buffer, valread, 0); // Send back the same message
        memset(buffer, 0, sizeof(buffer)); // Clear the buffer
    }

    close(new_socket);
    close(server_fd);
    return 0;
}

#---------ECHO client ---------------------------------------------------------------------------------------------------------

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

using namespace std;

#define PORT 8080 // Port number for the server

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    string message;

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cout << "Socket creation error" << endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET; // IPv4
    serv_addr.sin_port = htons(PORT); // Port

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        cout << "Invalid address/ Address not supported" << endl;
        return -1;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        cout << "Connection Failed" << endl;
        return -1;
    }

    // Send messages to the server
    while (true) {
        cout << "Enter message (type 'exit' to quit): ";
        getline(cin, message);
        if (message == "exit") {
            break; // Exit the loop if the user types 'exit'
        }
        send(sock, message.c_str(), message.length(), 0); // Send message to server
        int valread = read(sock, buffer, 1024); // Read the echoed message
        cout << "Echo from server: " << string(buffer, valread) << endl;
        memset(buffer, 0, sizeof(buffer)); // Clear the buffer
    }

    close(sock);
    return 0;
}

#-------- TCP/IP --------------------------------------------------------------------------------------------------------------

#-----------Chat server -------------------------------------------------------------------------------------------------------

#include <iostream>
#include <cstring>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <thread>

using namespace std;

#define PORT 8080 // Port number for the server
#define MAX_CLIENTS 10 // Maximum number of clients

vector<int> clients; // Vector to hold client sockets

void handleClient(int clientSocket) {
    char buffer[1024];
    int valread;

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        valread = read(clientSocket, buffer, 1024);
        if (valread <= 0) {
            cout << "Client disconnected." << endl;
            break;
        }
        cout << "Client: " << buffer << endl;

        // Echo the message back to all clients
        for (int client : clients) {
            if (client != clientSocket) {
                send(client, buffer, valread, 0);
            }
        }
    }

    // Remove the client from the list and close the socket
    close(clientSocket);
    clients.erase(remove(clients.begin(), clients.end(), clientSocket), clients.end());
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Attach socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET; // IPv4
    address.sin_addr.s_addr = INADDR_ANY; // Bind to any address
    address.sin_port = htons(PORT); // Port

    // Bind the socket to the address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("Listen");
        exit(EXIT_FAILURE);
    }

    cout << "Chat server is listening on port " << PORT << endl;

    while (true) {
        // Accept a connection
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept");
            exit(EXIT_FAILURE);
        }

        cout << "New client connected." << endl;
        clients.push_back(new_socket); // Add new client to the list

        // Create a new thread to handle the client
        thread(handleClient, new_socket).detach();
    }

    close(server_fd);
    return 0;
}

#------ CHAT CLIENT --------------------------------------------------------------------------------------------------------------

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <thread>

using namespace std;

#define PORT 8080 // Port number for the server

void receiveMessages(int sock) {
    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int valread = read(sock, buffer, 1024);
        if (valread <= 0) {
            cout << "Disconnected from server." << endl;
            break;
        }
        cout << "Server: " << buffer << endl;
    }
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    string message;

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cout << "Socket creation error" << endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET; // IPv4
    serv_addr.sin_port = htons(PORT); // Port

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        cout << "Invalid address/ Address not supported" << endl;
        return -1;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        cout << "Connection Failed" << endl;
        return -1;
    }

    // Start a thread to receive messages from the server
    thread(receiveMessages, sock).detach();

    //
 