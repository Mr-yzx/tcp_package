#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
// #include <pcap/pcap.h> // 仅用于生成示例PCAP头

#define HEADER_SIZE 40
#define RESERVED_SIZE 40
#define PCAP_HEADER_SIZE 24
#define MAX_PCAP_DATA_SIZE 1500
#define NUM_PACKETS 30000000  // 发送128个包，测试服务端批处理

// 生成示例PCAP文件头（24字节）
void generate_pcap_header(char *header) {
    // 简化的PCAP文件头
    uint32_t magic_number = 0xa1b2c3d4; // 标准PCAP magic number
    uint16_t version_major = htons(2);
    uint16_t version_minor = htons(4);
    int32_t thiszone = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = MAX_PCAP_DATA_SIZE;
    uint32_t network = 1; // LINKTYPE_ETHERNET
    
    memcpy(header, &magic_number, 4);
    memcpy(header + 4, &version_major, 2);
    memcpy(header + 6, &version_minor, 2);
    memcpy(header + 8, &thiszone, 4);
    memcpy(header + 12, &sigfigs, 4);
    memcpy(header + 16, &snaplen, 4);
    memcpy(header + 20, &network, 4);
}

// 生成示例PCAP帧数据
void generate_pcap_data(char *data, size_t size, int packet_num) {
    // 生成伪随机数据
    srand(time(NULL) + packet_num);
    for (size_t i = 0; i < size; i++) {
        data[i] = rand() % 256;
    }
    
    // 添加标识信息以便调试
    snprintf(data, size, "Packet %d: ", packet_num);
    size_t len = strlen(data);
    for (size_t i = len; i < size; i++) {
        data[i] = 'A' + (i % 26);
    }
}

int main(int argc, char* argv[]) {
    // if (argc != 3) {
    //     fprintf(stderr, "Usage: %s <server_ip> <port>\n", argv[0]);
    //     exit(EXIT_FAILURE);
    // }

    const char* server_ip = "172.16.103.90";
    int port = 8080;
    int sock;
    struct sockaddr_in server_addr;

    // 创建TCP套接字
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // 转换IP地址
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("invalid address");
        exit(EXIT_FAILURE);
    }

    // 连接服务器
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connection failed");
        exit(EXIT_FAILURE);
    }
    printf("Connected to server %s:%d\n", server_ip, port);

    // 准备缓冲区
    char packet_buffer[HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE + MAX_PCAP_DATA_SIZE];
    char pcap_header[PCAP_HEADER_SIZE];
    char pcap_data[MAX_PCAP_DATA_SIZE];
    
    // 生成PCAP文件头
    generate_pcap_header(pcap_header);

    // 发送多个数据包
    for (int i = 0; i < NUM_PACKETS; i++) {
        // 随机生成PCAP数据大小 (50-500字节)
        size_t pcap_data_size = 50 + (rand() % 1451);
        generate_pcap_data(pcap_data, pcap_data_size, i);
        
        // 计算总包长度 (不包括长度字段自身)
        uint32_t total_length = HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE + pcap_data_size - 4;
        
        // 设置长度字段（网络字节序）
        uint32_t net_length = htonl(total_length);
        memcpy(packet_buffer, &net_length, 4);
        
        // 填充头剩余部分（示例值）
        memset(packet_buffer + 4, 0xAA, HEADER_SIZE - 4);
        
        // 填充保留字段（示例值）
        memset(packet_buffer + HEADER_SIZE, 0xBB, RESERVED_SIZE);
        
        // 添加PCAP头
        memcpy(packet_buffer + HEADER_SIZE + RESERVED_SIZE, pcap_header, PCAP_HEADER_SIZE);
        
        // 添加PCAP数据
        memcpy(packet_buffer + HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE, 
               pcap_data, pcap_data_size);
        
        // 计算实际发送长度（包括长度字段）
        size_t send_length = 4 + total_length;
        
        // 发送数据包
        ssize_t bytes_sent = send(sock, packet_buffer, send_length, 0);
        if (bytes_sent < 0) {
            perror("send failed");
            break;
        }
        
        printf("Sent packet %d: total size=%zu, data size=%zu\n", 
               i+1, send_length, pcap_data_size);
        
        // 添加延迟以模拟真实网络
        usleep(100); // 10ms
    }
    while(1)
    {

    }
    printf("Sent %d packets. Closing connection.\n", NUM_PACKETS);
    close(sock);
    return 0;
}