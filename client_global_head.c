#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

// 数据包结构定义
#define HEADER_SIZE 40
#define RESERVED_SIZE 40
#define PCAP_HEADER_SIZE 24
#define MAX_PACKET_SIZE 65536  // 最大包大小

// PCAP全局文件头结构（24字节）
typedef struct {
    uint32_t magic_number;   // 文件标识
    uint16_t version_major;  // 主版本号
    uint16_t version_minor;  // 次版本号
    int32_t  thiszone;       // 时区修正
    uint32_t sigfigs;        // 时间戳精度
    uint32_t snaplen;        // 最大抓包长度
    uint32_t network;        // 链路类型
} pcap_global_header;

// PCAP包记录头结构（16字节）
typedef struct {
    uint32_t ts_sec;     // 时间戳秒
    uint32_t ts_usec;    // 时间戳微秒
    uint32_t incl_len;   // 实际捕获长度
    uint32_t orig_len;   // 原始包长度
} pcap_record_header;

int main(int argc, char* argv[]) {
    // if (argc != 4) {
    //     fprintf(stderr, "Usage: %s <server_ip> <port> <pcap_file>\n", argv[0]);
    //     exit(EXIT_FAILURE);
    // }

    const char* server_ip = "172.16.103.90";
    int port = 8080;
    const char* pcap_filename = argv[1];
    
    // 打开PCAP文件
    FILE* pcap_file = fopen(pcap_filename, "rb");
    if (!pcap_file) {
        perror("fopen failed");
        exit(EXIT_FAILURE);
    }
    
    // 读取PCAP全局文件头（24字节）
    pcap_global_header global_header;
    if (fread(&global_header, sizeof(pcap_global_header), 1, pcap_file) != 1) {
        perror("fread global header failed");
        fclose(pcap_file);
        exit(EXIT_FAILURE);
    }
    printf("global_head.network = %d\n",global_header.network);
    printf("global_head.snaplen = %d\n",global_header.snaplen);
    printf("global_head.thiszone = %d\n",global_header.thiszone);
    printf("global_head.sigfigs = %d\n",global_header.sigfigs);
    printf("global_head.magic_number = %x\n",global_header.magic_number);
    // 验证PCAP文件魔数
    if (global_header.magic_number != 0xa1b2c3d4 && 
        global_header.magic_number != 0xd4c3b2a1) {
        fprintf(stderr, "Invalid PCAP file format (magic: 0x%x)\n", 
                global_header.magic_number);
        fclose(pcap_file);
        exit(EXIT_FAILURE);
    }
    
    // 打印PCAP文件信息
    printf("PCAP file: %s\n", pcap_filename);
    printf("Version: %u.%u\n", global_header.version_major, global_header.version_minor);
    printf("Snaplen: %u, Network: %u\n", 
           global_header.snaplen, global_header.network);

    // 创建TCP套接字
    int sock;
    struct sockaddr_in server_addr;
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        fclose(pcap_file);
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // 转换IP地址
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("invalid address");
        fclose(pcap_file);
        close(sock);
        exit(EXIT_FAILURE);
    }

    // 连接服务器
    printf("Connecting to %s:%d...\n", server_ip, port);
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connection failed");
        fclose(pcap_file);
        close(sock);
        exit(EXIT_FAILURE);
    }
    printf("Connected to server\n");

    // 准备发送缓冲区
    uint8_t *packet_buffer = malloc(HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE + MAX_PACKET_SIZE);
    if (!packet_buffer) {
        perror("malloc failed");
        fclose(pcap_file);
        close(sock);
        exit(EXIT_FAILURE);
    }
    
    // 设置固定头部内容
    memset(packet_buffer + 4, 0xAA, HEADER_SIZE - 4);  // 头剩余部分
    memset(packet_buffer + HEADER_SIZE, 0xBB, RESERVED_SIZE); // 保留字段
    
    // 复制全局文件头到每个包的固定位置
    memcpy(packet_buffer + HEADER_SIZE + RESERVED_SIZE, 
           &global_header, sizeof(pcap_global_header));
    
    int packet_count = 0;
    size_t total_bytes_sent = 0;
    clock_t start_time = clock();
    
    // 读取并发送每个数据包
    while (!feof(pcap_file)) {
        pcap_record_header record_header;
        
        // 读取包记录头
        if (fread(&record_header, sizeof(pcap_record_header), 1, pcap_file) != 1) {
            if (feof(pcap_file)) break;
            perror("fread record header failed");
            break;
        }
        
      
        // 获取包数据长度
        uint32_t incl_len = ntohl(record_header.incl_len);
        if (incl_len == 0) {
            continue; // 跳过空包
        }
        
        if (incl_len > MAX_PACKET_SIZE) {
            fprintf(stderr, "Packet %d too large (%u > %d), truncating\n", 
                    packet_count + 1, incl_len, MAX_PACKET_SIZE);
            incl_len = MAX_PACKET_SIZE;
        }
        
        // 读取包数据
        uint8_t packet_data[MAX_PACKET_SIZE];
        if (fread(packet_data, incl_len, 1, pcap_file) != 1) {
            perror("fread packet data failed");
            break;
        }
        
        // 计算总包长度（不包括长度字段自身）
        uint32_t total_length = HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE + 
                                sizeof(pcap_record_header) + incl_len;
        
        // 设置长度字段（网络字节序）
        uint32_t net_length = htonl(total_length);
        memcpy(packet_buffer, &net_length, 4);
        
        // 复制记录头
        memcpy(packet_buffer + 4 + HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE, 
               &record_header, sizeof(pcap_record_header));
        
        // 复制包数据
        memcpy(packet_buffer + 4 + HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE + 
               sizeof(pcap_record_header), packet_data, incl_len);
        
        // 计算实际发送长度
        size_t send_length = 4 + total_length;
        
        // 发送数据包
        ssize_t bytes_sent = send(sock, packet_buffer, send_length, 0);
        if (bytes_sent < 0) {
            perror("send failed");
            break;
        }
        
        packet_count++;
        total_bytes_sent += bytes_sent;
        
        // 显示进度
        if (packet_count % 100 == 0) {
            printf("Sent %d packets, total bytes: %zu\n", packet_count, total_bytes_sent);
        }
        
        // 添加小延迟以控制发送速率
        usleep(2000);  // 2ms
    }
    
    // 计算性能统计
    clock_t end_time = clock();
    double elapsed_sec = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    double mb_sent = total_bytes_sent / (1024.0 * 1024.0);
    double mbps = (total_bytes_sent * 8) / (elapsed_sec * 1000000.0);
    
    printf("\nTransfer complete!\n");
    printf("Packets sent: %d\n", packet_count);
    printf("Total data: %.2f MB\n", mb_sent);
    printf("Time: %.2f seconds\n", elapsed_sec);
    printf("Rate: %.2f Mbps\n", mbps);
    
    // 清理资源
    free(packet_buffer);
    fclose(pcap_file);
    close(sock);
    
    return 0;
}