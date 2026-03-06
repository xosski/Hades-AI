// Code-1->Bit Stuffing and Destuffing(Verified)----------------------------------------------------------->

#include <iostream>
using namespace std;
void bitStuffing(string str, int n) {
    int count = 0;
    string stuffed = "";
    for (int i = 0; i < n; i++) {
        if (str[i] == '1') {
            count++;
            stuffed += str[i]; 
            if (count == 5) {
                stuffed += '0'; 
                count = 0; 
            }
        } else {
            count = 0; 
            stuffed += str[i]; 
        }
    }
    cout << "\nBit stuffing output is: " << stuffed;
    string destuffed = "";
    count = 0;
    for (int i = 0; i < stuffed.length(); i++) {
        if (stuffed[i] == '1') {
            count++;
            destuffed += stuffed[i];
        } else {
 
            if (count == 5) {
                count = 0;
                continue;
            } else {
                destuffed += stuffed[i];
                count = 0;
            }
        }
    }
 
    cout << "\nDestuffed output is: " << destuffed;
}
 
int main() {
    int n;
    cout << "Enter size of Data: ";
    cin >> n;
 
    cout << "Enter input data (only 0s and 1s): ";
    string str;
    cin >> str; 
      // Ensure the input size matches the expected size
    if (str.length() != n) {
        cout << "Error: Input data size does not match the specified size." << endl;
        return 1;
    }
 
    bitStuffing(str, n);
    return 0;
}
 

//2- Character Stuffing------------------------------------------------------------------------------>

 
#include<iostream>
using namespace std;
void Stuffing(string data, char sd, char ed){
    string stuff;
    stuff+=sd;
    for(int i=0;i<data.length();i++){
        if(data[i]!=ed && data[i]!=sd){
            stuff+=data[i];
        }
        else if(data[i]==ed){
            stuff+=ed;
            stuff+=data[i];
        }
        else{
            stuff+=sd;
            stuff+=data[i];
        }
    }
    stuff+=ed;
    cout<<"Stuffed data:"<<stuff;
    string destuff;
    for(int i=1;i<stuff.length()-1;i++){
        if(stuff[i]!=ed && stuff[i]!=sd)
        destuff+=stuff[i];
        else{
            destuff+=stuff[++i];
        }
    }
    cout<<"\nDestuffed Data:"<<destuff;
}
int main(){
    string data;
    cout<<"Enter stream of data:";
    cin>>data;
    char sd,ed;
    cout<<"Enter starting delimiter:";
    cin>>sd;
    cout<<"Enter ending delimiter:";
    cin>>ed;
    Stuffing(data,sd,ed);
}
 
 
//3-Hamming Code(Verified)------------------------------------------------------------------------>

 
#include <iostream>
#include <vector>
#include <cmath>
using namespace std;
int calculateParityBits(int dataBits) {
    int r = 0;
    while ((1 << r) < (dataBits + r + 1)) r++;
    return r;
}
 
vector<int> generateHammingCode(const vector<int>& data) {
    int dataBits = data.size();
    int parityBits = calculateParityBits(dataBits);
    int totalBits = dataBits + parityBits;
    vector<int> hammingCode(totalBits, 0);
    int dataIdx = 0;
    for (int i = 0; i < totalBits; i++) {
        if ((i + 1) & i) {
            hammingCode[i] = data[dataIdx++];
        }
    }
    for (int i = 0; i < parityBits; i++) {
        int pos = (1 << i);
        int parity = 0;
        for (int j = 0; j < totalBits; j++) {
            if ((j + 1) & pos) {
                parity ^= hammingCode[j];
            }
        }
        hammingCode[pos - 1] = parity;
    }
    return hammingCode;
}
 
int detectAndCorrectError(vector<int>& hammingCode) {
    int totalBits = hammingCode.size();
    int errorPos = 0;
    for (int i = 0; (1 << i) <= totalBits; i++) {
        int pos = (1 << i);
        int parity = 0;
        for (int j = 0; j < totalBits; j++) {
            if ((j + 1) & pos) {
                parity ^= hammingCode[j];
            }
        }
        if (parity != 0) {
            errorPos += pos;
        }
    }
    if (errorPos != 0) {
        cout << "Error detected at position: " << errorPos << endl;
        hammingCode[errorPos - 1] ^= 1;
    } else {
        cout << "No error detected." << endl;
    }
    return errorPos;
}
 
int main() {
    int n;
    cout << "Enter the number of data bits: ";
    cin >> n;
    vector<int> data(n);
    cout << "Enter the data bits (0 or 1): ";
    for (int i = 0; i < n; i++) {
        cin >> data[i];
    }
    vector<int> hammingCode = generateHammingCode(data);
    cout << "Generated Hamming code with parity bits (even parity): ";
    for (int bit : hammingCode) {
        cout << bit << " ";
    }
    cout << endl;
    hammingCode[2] ^= 1;
    cout << "Hamming code with an error introduced: ";
    for (int bit : hammingCode) {
        cout << bit << " ";
    }
    cout << endl;
    detectAndCorrectError(hammingCode);
    cout << "Corrected Hamming code: ";
    for (int bit : hammingCode) {
        cout << bit << " ";
    }
    cout << endl;
    return 0;
}

 
//Code-4->Checksum using noraml,1,2 complement...(verified)--------------------------------------------------->
 
 
#include <iostream>
#include <string>
#include <bitset>
#include <algorithm>
 
using namespace std;
 
int blockSize, numBlocks, method;
string sr;
 
// Function to add binary strings
string addBinary(const string& a, const string& b) {
    string result;
    int carry = 0;
    int i = a.length() - 1;
    int j = b.length() - 1;
 
    while (i >= 0 || j >= 0 || carry) {
        int sum = carry;
        if (i >= 0) sum += a[i--] - '0';
        if (j >= 0) sum += b[j--] - '0';
        result = char(sum % 2 + '0') + result;
        carry = sum / 2;
    }
 
    return result;
}
 
// Function to calculate checksum for sending data
string calculateChecksum(const string& data, int blockSize, int method) {
    string sum(blockSize, '0');
 
    for (size_t i = 0; i < data.length(); i += blockSize) {
        string block = data.substr(i, blockSize);
        sum = addBinary(sum, block);
 
        // Perform end-around carry
        if (sum.length() > blockSize) {
            sum = addBinary(sum.substr(sum.length() - blockSize), sum.substr(0, sum.length() - blockSize));
        }
    }
 
    // Ensure sum is exactly blockSize bits
    sum = sum.substr(sum.length() - blockSize);
 
    string checksum;
    switch (method) {
        case 0: // Normal checksum
            checksum = sum;
            break;
        case 1: // 1's complement
            checksum = string(blockSize, '1');
            for (size_t i = 0; i < blockSize; ++i) {
                checksum[i] = (sum[i] == '0') ? '1' : '0';
            }
            break;
        case 2: // 2's complement
            checksum = string(blockSize, '1');
            for (size_t i = 0; i < blockSize; ++i) {
                checksum[i] = (sum[i] == '0') ? '1' : '0';
            }
            checksum = addBinary(checksum, string(blockSize - 1, '0') + "1");
            checksum = checksum.substr(checksum.length() - blockSize);
            break;
        default:
            cerr << "Invalid checksum method" << endl;
            return "";
    }
    return checksum;
}
 
// Sender function
void sender() {
 
    string data = "";
 
    cout << "Enter block size: ";
    cin >> blockSize;
    cout << "Enter number of blocks: ";
    cin >> numBlocks;
 
    for (int i = 0; i < numBlocks; ++i) {
        string block;
        cout << "Enter block " << i + 1 << ": ";
        cin >> block;
        data += block;
    }
 
    cout << "Concatenated data: " << data << endl;
 
    cout << "Choose checksum method (0: Normal, 1: 1's complement, 2: 2's complement): ";
    cin >> method;
 
    string checksum = calculateChecksum(data, blockSize, method);
    sr=data+checksum;
    cout << "Original data: " << data << endl;
    cout << "Checksum: " << checksum << endl;
    cout << "Data to be transmitted: " << data << checksum << endl;
}
 
// Receiver function
void receiver() {
    string receivedData=sr;
    int errorPosition;
    char newBit;
 
 
    cout << "Enter position to introduce error (0 for no error): ";
    cin >> errorPosition;
 
    // If error position is provided, ask for the new bit
    if (errorPosition > 0 && errorPosition <= receivedData.length()) {
        cout << "Enter new bit at position " << errorPosition << ": ";
        cin >> newBit;
 
        // Only modify if the new bit is different from the existing one
        if (receivedData[errorPosition - 1] != newBit) {
            receivedData[errorPosition - 1] = newBit;
            cout << "Received Data after error introduction: " << receivedData << endl;
        } else {
            cout << "No change in data as the bit at the specified position is the same as before." << endl;
        }
    } else {
        cout << "No error introduced. Received Data: " << receivedData << endl;
    }
 
    // Add all data blockwise including checksum
    string finalSum(blockSize, '0');
    for (size_t i = 0; i < receivedData.length(); i += blockSize) {
        string block = receivedData.substr(i, blockSize);
        finalSum = addBinary(finalSum, block);
 
        // Perform end-around carry if needed
        if (finalSum.length() > blockSize) {
            finalSum = addBinary(finalSum.substr(finalSum.length() - blockSize), finalSum.substr(0, finalSum.length() - blockSize));
        }
    }
 
    // Ensure finalSum is exactly blockSize bits
    finalSum = finalSum.substr(finalSum.length() - blockSize);
 
    // Determine if error exists based on checksum method
    bool isError = false;
    if (method == 1) {  // 1's complement
        // 1's complement validation: if finalSum is all 1's, no error
        isError = (finalSum != string(blockSize, '1'));
    } else if (method == 2) {  // 2's complement
        // 2's complement validation: if finalSum is all 0's, no error
        isError = (finalSum != string(blockSize, '0'));
    }
 
    cout << "Calculated Final Sum: " << finalSum << endl;
    if (!isError) {
        cout << "No error detected." << endl;
    } else {
        cout << "Error detected!" << endl;
    }
}
 
int main() {
    sender();
    receiver();
 
    return 0;
}
 
//5-CRC 12,16,32,ccitt(Verified)---------------------------------------------------------------------------->

 
#include <bits/stdc++.h>
#define MAX_POLY_LENGTH 33
#define MAX_DATA_LENGTH 256
 
using namespace std;
 
string data;
string checkvalue, genpoly;
int polylen, datalen;
 
string CRC_12_POLY = "1100000001111";
string CRC_16_POLY = "11000000000000101";
string CRC_32_POLY = "100000100110000010001110110110111";
string CRC_CCITT_POLY = "100000100110000010001110110110111";
 
void xorOp()
{
    for (size_t j = 1; j < polylen; ++j)
    {
        checkvalue[j] = (checkvalue[j] == genpoly[j]) ? '0' : '1';
    }
}
 
void crcCalc()
{
    checkvalue = ::data.substr(0, polylen);
    for (size_t i = polylen; i <= datalen + polylen - 1; ++i)
    {
        if (checkvalue[0] == '1')
            xorOp();
        checkvalue = checkvalue.substr(1) + ::data[i];
    }
}
 
void receiver()
{
    cout << "Enter the received data: ";
    cin >> ::data;
    crcCalc();
 
    // Print the final remainder
    cout << "\nFinal remainder: " << checkvalue << endl;
 
    // Check if there is an error by examining if the remainder is non-zero
    bool errorDet = false;
    for (size_t i = 0; i < polylen - 1; ++i)
    {
        if (checkvalue[i] == '1')
        {
            errorDet = true;
            break;
        }
    }
 
    if (errorDet)
    {
        cout << "Error detected.\n";
    }
    else
    {
        cout << "No error detected.\n";
    }
}
 
int main()
{
    int choice;
    cout << "Select CRC type:\n 1. CRC-12\n 2. CRC-16\n 3. CRC-32\n 4. CRC-CCITT\n Enter your choice (1/2/3/4): ";
    cin >> choice;
    switch (choice)
    {
        case 1: genpoly = CRC_12_POLY; break;
        case 2: genpoly = CRC_16_POLY; break;
        case 3: genpoly = CRC_32_POLY; break;
        case 4: genpoly = CRC_CCITT_POLY; break;
        default: cout << "Invalid choice...exiting..\n"; return 1;
    }
    polylen = genpoly.length();
    cout << "\nEnter data to be transmitted: ";
    cin >> ::data;
    datalen = ::data.length();
    ::data.append(polylen - 1, '0');
    crcCalc();
    cout << "\nCRC or checkvalue is: " << checkvalue << endl;
    ::data.replace(datalen, polylen - 1, checkvalue);
    cout << "\nFinal data to be sent: " << ::data << endl;
    receiver();
    return 0;
}
 
//6-Hostname, ipv4, class, networkID and HostID ------------------------------------------------------------------>

 
#include <iostream>
#include <unistd.h>      
#include <netdb.h>       
#include <arpa/inet.h>  
using namespace std;
void determineClassAndIDs(const string &ip) {
    int firstOctet = stoi(ip.substr(0, ip.find('.')));
    char ipClass;
    if (firstOctet >= 1 && firstOctet <= 126) ipClass = 'A';
    else if (firstOctet >= 128 && firstOctet <= 191) ipClass = 'B';
    else if (firstOctet >= 192 && firstOctet <= 223) ipClass = 'C';
    else if (firstOctet >= 224 && firstOctet <= 239) ipClass = 'D';
    else ipClass = 'E';
    cout << "IP Class: " << ipClass << endl;
    string networkID, hostID;
    size_t pos = ip.find('.');
    if (ipClass == 'A') {
        networkID = ip.substr(0, pos);
        hostID = ip.substr(pos + 1);
    } else if (ipClass == 'B') {
        pos = ip.find('.', pos + 1);
        networkID = ip.substr(0, pos);
        hostID = ip.substr(pos + 1);
    } else if (ipClass == 'C') {
        pos = ip.find('.', ip.find('.', pos + 1) + 1);
        networkID = ip.substr(0, pos);
        hostID = ip.substr(pos + 1);
    } else {
        networkID = "N/A";
        hostID = "N/A";
    }
    cout << "Network ID: " << networkID << endl;
    cout << "Host ID: " << hostID << endl;
}
 
int main() {
    char hostname[256];
 
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        cerr << "Error getting hostname!" << endl;
        return 1;
    }
    cout << "Hostname: " << hostname << endl;
    struct hostent *host_entry = gethostbyname(hostname);
    if (!host_entry) {
        cerr << "Error getting host information!" << endl;
        return 1;
    }
    char *ip = inet_ntoa(*(struct in_addr*)host_entry->h_addr_list[0]);
    cout << "IP Address: " << ip << endl;
    determineClassAndIDs(string(ip));
    return 0;
}
 
 
//7- IPV4 to 32 bit address-------------------------------------------------------------------------->

 
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <bitset>
using namespace std;
 
uint32_t dottedTo32Bit(const string &ipAddress) {
    struct sockaddr_in sa;
    inet_pton(AF_INET, ipAddress.c_str(), &(sa.sin_addr));
    return ntohl(sa.sin_addr.s_addr);
}
 
string toBinary(uint32_t n) {
    return bitset<32>(n).to_string(); // Converts to 32-bit binary string
}
 
int main() {
    struct ifaddrs *ifaddr;
 
    if (getifaddrs(&ifaddr) == -1) {
        cerr << "Error getting network interfaces!" << endl;
        return 1;
    }
    for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            char ipAddress[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ipAddress, sizeof(ipAddress));
 
            if (strcmp(ipAddress, "127.0.0.1") == 0) {
                continue;
            }
 
            uint32_t ip32 = dottedTo32Bit(ipAddress);
 
            cout << "IPv4 Address: " << ipAddress << endl;
            cout << "32-bit Representation (Binary): " << toBinary(ip32) << endl;
        }
    }
 
    freeifaddrs(ifaddr);
    return 0;
}
 
 
//8- Dijkstra Algo------------------------------------------------------------------------------------->

 
#include <iostream>
#include <vector>
#include <climits>
#include <queue>
using namespace std;
 
class Graph {
public:
    int V;
    vector<vector<pair<int, int>>> adjList;
    Graph(int vertices) {
        V = vertices;
        adjList.resize(V);
    }
 
    void addEdge(int u, int v, int weight) {
        adjList[u].push_back({v, weight});
        adjList[v].push_back({u, weight});
    }
 
    void dijkstra(int src) {
        priority_queue<pair<int, int>, vector<pair<int, int>>, greater<pair<int, int>>> pq;
        vector<int> dist(V, INT_MAX);
        pq.push({0, src});
        dist[src] = 0;
        while (!pq.empty()) {
            int u = pq.top().second;
            int d = pq.top().first;
            pq.pop();
            if (d > dist[u]) continue;
            for (auto neighbor : adjList[u]) {
                int v = neighbor.first;
                int weight = neighbor.second;
                if (dist[u] + weight < dist[v]) {
                    dist[v] = dist[u] + weight;
                    pq.push({dist[v], v});
                }
            }
        }
        printSolution(dist);
    }
    void printSolution(vector<int> dist) {
        cout << "Vertex   Distance from Source\n";
        for (int i = 0; i < V; i++) {
            cout << i << " \t\t " << dist[i] << endl;
        }
    }
};
 
int main() {
    int V, E;
    cout << "Enter the number of vertices: ";
    cin >> V;
    Graph g(V);
    cout << "Enter the number of edges: ";
    cin >> E;
    cout << "Enter the edges (u v weight) where u, v are vertices and weight is the edge weight:\n";
    for (int i = 0; i < E; i++) {
        int u, v, weight;
        cin >> u >> v >> weight;
        g.addEdge(u, v, weight);
    }
    int source;
    cout << "Enter the source vertex (0 to " << V-1 << "): ";
    cin >> source;
    g.dijkstra(source);
    return 0;
}



7 (A) :-------------------------------------------------------------------------------------------->
 
#include <iostream>
#include <cstring>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
 
void get_ip_class_and_ids(const std::string& ip, char& ip_class, std::string& network_id, std::string& host_id) {
    struct in_addr addr;
    inet_pton(AF_INET, ip.c_str(), &addr);
    unsigned long ipnum = ntohl(addr.s_addr);
 
    if ((ipnum & 0x80000000) == 0x00000000) { // Class A
        ip_class = 'A';
        network_id = ip.substr(0, ip.find('.'));
        host_id = ip.substr(ip.find('.') + 1);
    } else if ((ipnum & 0xC0000000) == 0x80000000) { // Class B
        ip_class = 'B';
        size_t pos = ip.find('.', ip.find('.') + 1);
        network_id = ip.substr(0, pos);
        host_id = ip.substr(pos + 1);
    } else if ((ipnum & 0xE0000000) == 0xC0000000) { // Class C
        ip_class = 'C';
        size_t pos = ip.find('.', ip.find('.', ip.find('.') + 1) + 1);
        network_id = ip.substr(0, pos);
        host_id = ip.substr(pos + 1);
    } else if ((ipnum & 0xF0000000) == 0xE0000000) { // Class D
        ip_class = 'D';
        network_id = "N/A";
        host_id = "N/A";
    } else { // Class E
        ip_class = 'E';
        network_id = "N/A";
        host_id = "N/A";
    }
}
 
int main() {
    char hostname[1024];
    gethostname(hostname, sizeof(hostname));
    std::cout << "Hostname: " << hostname << std::endl;
 
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char ip[INET_ADDRSTRLEN];
 
    getifaddrs(&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family == AF_INET) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, ip, INET_ADDRSTRLEN);
            std::string ip_str = ip;
            if (ip_str != "127.0.0.1") { // Skip loopback address
                std::cout << "IPv4 Address: " << ip_str << std::endl;
 
                char ip_class;
                std::string network_id, host_id;
                get_ip_class_and_ids(ip_str, ip_class, network_id, host_id);
 
                std::cout << "IP Class: " << ip_class << std::endl;
                std::cout << "Network ID: " << network_id << std::endl;
                std::cout << "Host ID: " << host_id << std::endl;
            }
        }
    }
    freeifaddrs(ifap);
 
    return 0;
}
 
 
7 (B) :--------------------------------------------------------------------------------------------->
 
#include <iostream>
#include <arpa/inet.h>
#include <bitset>
#include <sstream>
 
std::string dotted_decimal_to_32bit(const std::string& ip) {
    struct in_addr addr;
    inet_pton(AF_INET, ip.c_str(), &addr);
 
    uint32_t ip_num = ntohl(addr.s_addr);
 
    std::stringstream ss;
    ss << std::bitset<32>(ip_num);
    return ss.str();
}
 
int main() {
    std::string ip = "192.168.1.1"; // Replace this with your system's IP address
 
    std::string bit_32 = dotted_decimal_to_32bit(ip);
 
    std::cout << "IPv4 Address: " << ip << std::endl;
    std::cout << "32-bit Address: " << bit_32 << std::endl;
 
    return 0;
}
 


Q8. DISTANCE VECTOR ALGORTHM -------------------------------------------------------------------------->

#include <iostream>
#include <vector>
#include <map>
#include <limits>

const int INF = std::numeric_limits<int>::max();

struct Router {
    std::map<int, int> distance_vector;
    std::map<int, int> next_hop;
};

void initialize_routers(std::vector<Router>& routers, const std::vector<std::vector<int>>& cost_matrix) {
    int n = cost_matrix.size();
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            routers[i].distance_vector[j] = cost_matrix[i][j];
            if (cost_matrix[i][j] != INF && i != j) {
                routers[i].next_hop[j] = j;
            } else {
                routers[i].next_hop[j] = -1;  // Indicating no direct route
            }
        }
    }
}

void distance_vector_routing(std::vector<Router>& routers) {
    bool updated = true;
    int n = routers.size();
    while (updated) {
        updated = false;
        for (int i = 0; i < n; ++i) {
            for (int j = 0; j < n; ++j) {
                for (int k = 0; k < n; ++k) {
                    if (routers[i].distance_vector[j] > routers[i].distance_vector[k] + routers[k].distance_vector[j]) {
                        routers[i].distance_vector[j] = routers[i].distance_vector[k] + routers[k].distance_vector[j];
                        routers[i].next_hop[j] = k;
                        updated = true;
                    }
                }
            }
        }
    }
}

void print_routing_table(const std::vector<Router>& routers) {
    int n = routers.size();
    for (int i = 0; i < n; ++i) {
        std::cout << "Router " << i << ":\n";
        std::cout << "Destination\tCost\tNext Hop\n";
        for (int j = 0; j < n; ++j) {
            if (routers[i].distance_vector.at(j) != INF) {
                std::cout << j << "\t\t" << routers[i].distance_vector.at(j) << "\t\t";
                if (routers[i].next_hop.at(j) != -1) {
                    std::cout << routers[i].next_hop.at(j) << "\n";
                } else {
                    std::cout << "N/A\n";
                }
            } else {
                std::cout << j << "\t\tINF\t\tN/A\n";
            }
        }
        std::cout << "\n";
    }
}

int main() {
    // Example cost matrix
    std::vector<std::vector<int>> cost_matrix = {
        {0, 1, 4, INF, INF},
        {1, 0, 4, 2, 7},
        {4, 4, 0, 3, INF},
        {INF, 2, 3, 0, 1},
        {INF, 7, INF, 1, 0}
    };

    int n = cost_matrix.size();
    std::vector<Router> routers(n);

    initialize_routers(routers, cost_matrix);
    distance_vector_routing(routers);
    print_routing_table(routers);

    return 0;
}


Q9. - SOCKET CODE FOR ECHO COMMAND--------------------------------------------------------------------->
 
[{Server Side}] ____________________________________
 
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
using namespace std;
#define PORT 65432
 
int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
 
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }
 
    // Setting up address structure
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
 
    // Bind the socket to the port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
 
    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    std::cout << "Server listening on port " << PORT << std::endl;
 
    // Accept incoming connection
    if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
        perror("Accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
 
    // Echo loop
    while (true) {
        int valread = read(new_socket, buffer, 1024);
        if (valread <= 0) {
            break;
        }
        cout << "Received: " << buffer << std::endl;
        send(new_socket, buffer, valread, 0);
        memset(buffer, 0, sizeof(buffer));  // Clear buffer
    }
 
    close(new_socket);
    close(server_fd);
    return 0;
}
 
[{Client Side}] ____________________________________________
 
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
using namespace std;
#define PORT 65432
 
int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
 
    // Create socket file descriptor
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "Socket creation error" << std::endl;
        return -1;
    }
 
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
 
    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        cerr << "Invalid address or address not supported" << std::endl;
        return -1;
    }
 
    // Connect to the server
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        cerr << "Connection Failed" << std::endl;
        return -1;
    }
 
    while (true) {
        cout << "Enter message to echo (type 'exit' to quit): ";
        string message;
        getline(std::cin, message);
 
        if (message == "exit") {
            break;
        }
 
        // Send message to server
        send(sock, message.c_str(), message.size(), 0);
 
        // Receive echoed message from server
        int valread = read(sock, buffer, 1024);
        cout << "Received echo: " << buffer << std::endl;
 
        memset(buffer, 0, sizeof(buffer));  // Clear buffer
    }
 
    close(sock);
    return 0;
}
 


Q10. - Write a program to demonstrate client-server application for chat using TCP/IP.---------------------------------------------->
 
Server side code __________________________________

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
using namespace std;
#define PORT 65432
 
int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
 
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }
 
    // Setup address structure
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
 
    // Bind the socket to the address
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
 
    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    cout << "Server listening on port " << PORT << std::endl;
 
    // Accept a connection
    if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
        perror("Accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    cout << "Client connected." << std::endl;
 
    while (true) {
        // Receive message from client
        int valread = read(new_socket, buffer, 1024);
        if (valread <= 0) {
            std::cout << "Client disconnected." << std::endl;
            break;
        }
        cout << "Client: " << buffer << std::endl;
 
        // Get reply from server
        cout << "Server: ";
        string message;
        getline(std::cin, message);
        send(new_socket, message.c_str(), message.size(), 0);
 
        memset(buffer, 0, sizeof(buffer)); // Clear buffer
    }
 
    close(new_socket);
    close(server_fd);
    return 0;
}
 
Client Side Code _________________________________

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
using namespace std;
#define PORT 65432
 
int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
 
    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "Socket creation error" << std::endl;
        return -1;
    }
 
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
 
    // Convert IPv4 address from text to binary
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        cerr << "Invalid address or address not supported" << std::endl;
        return -1;
    }
 
    // Connect to the server
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        cerr << "Connection Failed" << std::endl;
        return -1;
    }
    cout << "Connected to server." << std::endl;
 
    while (true) {
        // Send message to server
        cout << "Client: ";
        string message;
        getline(std::cin, message);
        send(sock, message.c_str(), message.size(), 0);
 
        // Receive reply from server
        int valread = read(sock, buffer, 1024);
        if (valread <= 0) {
            cout << "Server disconnected." << std::endl;
            break;
        }
        cout << "Server: " << buffer << std::endl;
 
        memset(buffer, 0, sizeof(buffer)); // Clear buffer
    }
 
    close(sock);
    return 0;
}