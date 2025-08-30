#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include <errno.h>

#define HEADER_SIZE 40          // 包括前4字节长度字段
#define RESERVED_SIZE 40
#define PCAP_HEADER_SIZE 24
#define COMMON_HEAD_SIZE 12     // packetlen + totallen + seqnum
#define MAX_FRAMES_PER_BIG 64
#define RECV_BUFFER_SIZE 65536
#define PCAP_MAGIC_BIG_ENDIAN 0xA1B2C3D4
#define PCAP_MAGIC_LITTLE_ENDIAN 0xD4C3B2A1

// 通用包头结构 (12字节)
#pragma pack(push, 1)
typedef struct {
    uint32_t packetlen;  // 当前帧数据长度
    uint32_t totallen;   // 当前包总长度（包括包头）
    uint32_t seqnum;     // 序列号（大包中表示小包数量）
    uint8_t data[];      // 柔性数组，存放实际数据
} CommonHead;

// 全局缓冲区管理
typedef struct {
    uint8_t* buffer;
    size_t size;
    size_t len;
} Buffer;
#pragma pack(pop)
Buffer* create_buffer(size_t initial_size) {
    Buffer* buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) return NULL;
    
    buf->buffer = (uint8_t *)malloc(initial_size);
    if (!buf->buffer) {
        free(buf);
        return NULL;
    }
    
    buf->size = initial_size;
    buf->len = 0;
    return buf;
}

void append_to_buffer(Buffer* buf, const uint8_t* data, size_t len) {
    if (buf->len + len > buf->size) {
        size_t new_size = buf->size * 2;
        while (buf->len + len > new_size) new_size *= 2;
        
        uint8_t* new_buf = (uint8_t *)realloc(buf->buffer, new_size);
        if (!new_buf) {
            perror("realloc failed");
            return;
        }
        
        buf->buffer = new_buf;
        buf->size = new_size;
    }
    memcpy(buf->buffer + buf->len, data, len);
    buf->len += len;
}

void consume_buffer(Buffer* buf, size_t len) {
    if (len > buf->len) len = buf->len;
    if (len < buf->len) {
        memmove(buf->buffer, buf->buffer + len, buf->len - len);
    }
    buf->len -= len;
}

void free_buffer(Buffer* buf) {
    if (buf) {
        free(buf->buffer);
        free(buf);
    }
}

// TCP服务器初始化
int setup_tcp_server(int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        return -1;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        close(server_fd);
        return -1;
    }
    struct sockaddr_in address;
    // struct sockaddr_in address = {
    //     .sin_family = AF_INET,
    //     .sin_addr.s_addr = INADDR_ANY,
    //     .sin_port = htons(port)
    // };
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        return -1;
    }

    return server_fd;
}

// 验证PCAP魔术字
int validate_pcap_magic(const uint8_t* data) {
    uint32_t magic = *(const uint32_t*)data;
    return (magic == PCAP_MAGIC_BIG_ENDIAN || 
            magic == PCAP_MAGIC_LITTLE_ENDIAN);
}

// 创建小包
CommonHead* create_small_packet(const uint8_t* pcap_data, uint32_t data_len) {
    printf("data_len = %d\n",data_len);
    uint32_t total_size = COMMON_HEAD_SIZE + data_len;
    CommonHead* packet = (CommonHead*)malloc(total_size);
    if (!packet) return NULL;
    
    // 设置包头字段（主机字节序）
    packet->packetlen = data_len;    // 帧数据长度
    packet->totallen = total_size;    // 整个小包长度
    packet->seqnum = 0;               // 小包中不使用
    
    // 复制数据
    // printf("pcap_data = %s\n",pcap_data);
    memcpy(packet->data, pcap_data, data_len);
    
    // 转换为网络字节序
    packet->packetlen = htonl(packet->packetlen);
    packet->totallen = htonl(packet->totallen);
    packet->seqnum = htonl(packet->seqnum);
    
    return packet;
}

// 创建大包（包含多个小包）
CommonHead* create_big_packet(CommonHead** small_packets, int count) {
    // 计算大包总长度
    uint32_t total_data_size = 0;
    for (int i = 0; i < count; i++) {
        // 注意：小包的totallen是网络字节序
        total_data_size += ntohl(small_packets[i]->totallen);
    }
    
    uint32_t big_total_size = COMMON_HEAD_SIZE + total_data_size;
    CommonHead* big_packet = (CommonHead *)malloc(big_total_size);
    if (!big_packet) return NULL;
    
    // 设置大包头字段（主机字节序）
    big_packet->packetlen = total_data_size;  // 数据部分总长度
    big_packet->totallen = big_total_size;    // 整个大包长度
    big_packet->seqnum = count;               // 包含的小包数量
    
    // 转换为网络字节序
    big_packet->packetlen = htonl(big_packet->packetlen);
    big_packet->totallen = htonl(big_packet->totallen);
    big_packet->seqnum = htonl(big_packet->seqnum);
    
    // 复制所有小包数据
    uint8_t* pos = big_packet->data;
    for (int i = 0; i < count; i++) {
        uint32_t small_size = ntohl(small_packets[i]->totallen);
        memcpy(pos, small_packets[i], small_size);
        pos += small_size;
        
        // 释放小包内存
        free(small_packets[i]);
    }
    
    return big_packet;
}

// 处理接收到的数据包
void process_packet(Buffer* recv_buf, CommonHead** frame_list, int* frame_count, 
                   void (*send_big_packet)(CommonHead*)) {
    while (recv_buf->len >= 4) {
        // 解析包长度 (小端序)
        uint32_t packet_len = *(uint32_t*)recv_buf->buffer;
        packet_len = ntohl(packet_len);
        uint32_t total_packet_size = packet_len + 4; // 包含4字节长度字段

        // 检查是否收到完整包
        if (recv_buf->len < total_packet_size) break;

        // 验证最小包长度 (HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE = 104字节)
        if (total_packet_size < HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE) {
            fprintf(stderr, "Packet too small: %u bytes, skipping\n", total_packet_size);
            consume_buffer(recv_buf, total_packet_size);
            continue;
        }

        // 计算魔术字位置 (HEADER_SIZE + RESERVED_SIZE = 80字节)
        const uint8_t* pcap_header = recv_buf->buffer + HEADER_SIZE + RESERVED_SIZE;
        
        // 验证PCAP魔术字
        if (!validate_pcap_magic(pcap_header)) {
            fprintf(stderr, "Invalid PCAP magic: 0x%08X, skipping packet\n", *(uint32_t*)pcap_header);
            consume_buffer(recv_buf, total_packet_size);
            continue;
        }

        // 计算PCAP数据位置 (HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE = 104字节)
        uint32_t pcap_data_offset = HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE;
        uint32_t pcap_data_len = total_packet_size - pcap_data_offset;

        // 检查PCAP数据长度
        if (pcap_data_len == 0) {
            fprintf(stderr, "Zero-length PCAP data, skipping\n");
            consume_buffer(recv_buf, total_packet_size);
            continue;
        }

        // 创建小包
        CommonHead* small_pkt = create_small_packet(
            recv_buf->buffer + pcap_data_offset, 
            pcap_data_len
        );
        
        if (!small_pkt) {
            perror("Failed to create small packet");
            consume_buffer(recv_buf, total_packet_size);
            continue;
        }

        // 添加到帧列表
        if (*frame_count < MAX_FRAMES_PER_BIG) {
            frame_list[*frame_count] = small_pkt;
            (*frame_count)++;
        } else {
            fprintf(stderr, "Frame list full, discarding packet\n");
            free(small_pkt);
        }

        // 如果收集到足够帧数，发送大包
        if (*frame_count == MAX_FRAMES_PER_BIG) {
            CommonHead* big_packet = create_big_packet(frame_list, *frame_count);
            if (big_packet) {
                send_big_packet(big_packet);
            } else {
                perror("Failed to create big packet");
                // 清理小包资源
                for (int i = 0; i < *frame_count; i++) {
                    free(frame_list[i]);
                }
            }
            *frame_count = 0;
        }

        // 从缓冲区移除已处理数据
        consume_buffer(recv_buf, total_packet_size);
    }
}

// 示例发送函数
void example_send_big_packet(CommonHead* big_packet) {
    // 将包头转换为主机字节序以便读取
    uint32_t packetlen = ntohl(big_packet->packetlen);
    uint32_t totallen = ntohl(big_packet->totallen);
    uint32_t seqnum = ntohl(big_packet->seqnum);
    
    printf("Sending big packet: seqnum=%u, packetlen=%u, totallen=%u\n", 
           seqnum, packetlen, totallen);
    
    // 实际发送代码 (如保存到文件或发送到网络)
    // 这里简单释放内存
    free(big_packet);
}

// 处理剩余帧
void flush_remaining_frames(CommonHead** frame_list, int frame_count, 
                           void (*send_big_packet)(CommonHead*)) {
    if (frame_count <= 0) return;
    
    printf("Sending partial packet with %d frames\n", frame_count);
    
    CommonHead* big_packet = create_big_packet(frame_list, frame_count);
    if (big_packet) {
        send_big_packet(big_packet);
    } else {
        perror("Failed to create partial big packet");
        // 清理小包资源
        for (int i = 0; i < frame_count; i++) {
            free(frame_list[i]);
        }
    }
}

int main(int argc, char* argv[]) {
    // if (argc != 2) {
    //     fprintf(stderr, "Usage: %s <port>\n", argv[0]);
    //     return EXIT_FAILURE;
    // }

    int port = 8080;
    int server_fd = setup_tcp_server(port);
    if (server_fd < 0) {
        return EXIT_FAILURE;
    }

    printf("Server listening on port %d\n", port);

    Buffer* recv_buf = create_buffer(RECV_BUFFER_SIZE);
    if (!recv_buf) {
        close(server_fd);
        return EXIT_FAILURE;
    }
    
    CommonHead* frame_list[MAX_FRAMES_PER_BIG];
    int frame_count = 0;

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }

        printf("Client connected from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), 
               ntohs(client_addr.sin_port));

        uint8_t temp_buf[4096];
        while (1) {
            ssize_t n = recv(client_sock, temp_buf, sizeof(temp_buf), 0);
            if (n <= 0) {
                if (n == 0) {
                    printf("Client disconnected\n");
                } else {
                    perror("recv failed");
                }
                break;
            }
            printf("n = %d\n",n);
            // 添加到接收缓冲区
            append_to_buffer(recv_buf, temp_buf, n);

            // 处理缓冲区中的数据
            process_packet(recv_buf, frame_list, &frame_count, example_send_big_packet);
        }

        // 处理剩余未满64帧的数据
        flush_remaining_frames(frame_list, frame_count, example_send_big_packet);
        frame_count = 0;
        
        close(client_sock);
    }

    close(server_fd);
    free_buffer(recv_buf);
    return EXIT_SUCCESS;
}