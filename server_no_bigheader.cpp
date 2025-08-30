#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define HEADER_SIZE 40
#define RESERVED_SIZE 40
#define PCAP_HEADER_SIZE 24
#define CUSTOM_HEADER_SIZE 30
#define FRAME_BATCH_SIZE 64

typedef struct {
    char* data;         // 帧数据指针
    size_t length;      // 帧数据长度
    char custom_header[CUSTOM_HEADER_SIZE]; // 自定义头
} Frame;

// 后续处理函数（示例）
void process_frames(Frame* frames, int count) {
    printf("Processing batch of %d frames\n", count);
    for (int i = 0; i < count; i++) {
        printf("Frame %d: Custom header + %zu bytes payload\n", 
               i, frames[i].length);
        // 实际应用中这里进行数据处理（如写入文件、转发等）
    }
}

int main(int argc, char* argv[]) {
    // if (argc != 2) {
    //     fprintf(stderr, "Usage: %s <port>\n", argv[0]);
    //     exit(EXIT_FAILURE);
    // }

    int port = 8080;
    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    // 创建TCP套接字
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // 设置套接字选项
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // 绑定端口
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // 开始监听
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", port);

    // 接受客户端连接
    if ((client_fd = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
        perror("accept failed");
        exit(EXIT_FAILURE);
    }
    printf("Client connected\n");

    // 初始化帧收集数组
    Frame frame_batch[FRAME_BATCH_SIZE];
    int frame_count = 0;
    
    // 接收缓冲区
    char buffer[4096];
    ssize_t bytes_received;
    size_t data_offset = 0;  // 缓冲区中已处理数据偏移量
    
    // 主接收循环
    while ((bytes_received = recv(client_fd, buffer + data_offset, sizeof(buffer) - data_offset, 0)) > 0) {
        size_t total_bytes = data_offset + bytes_received;
        size_t current_offset = 0;

        // 处理缓冲区中的所有完整数据包
        while (current_offset + 4 <= total_bytes) {
            // 读取包长度（网络字节序）
            uint32_t pkt_length;
            memcpy(&pkt_length, buffer + current_offset, 4);
            pkt_length = ntohl(pkt_length);
            size_t full_pkt_length = pkt_length + 4;

            // 检查是否收到完整数据包
            if (current_offset + full_pkt_length > total_bytes) {
                break;
            }

            // 计算PCAP数据位置和长度
            size_t pcap_offset = current_offset + HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE;
            size_t pcap_length = full_pkt_length - (HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE);

            // 检查PCAP数据有效性
            if (pcap_length > 0) {
                // 准备帧数据
                if (frame_count < FRAME_BATCH_SIZE) {
                    Frame* current_frame = &frame_batch[frame_count];
                    
                    // 填充自定义头（示例：全零，实际应用可修改）
                    memset(current_frame->custom_header, 0, CUSTOM_HEADER_SIZE);
                    
                    // 复制PCAP数据
                    current_frame->data = (char *)malloc(pcap_length);
                    if (!current_frame->data) {
                        perror("malloc failed");
                        exit(EXIT_FAILURE);
                    }
                    memcpy(current_frame->data, buffer + pcap_offset, pcap_length);
                    current_frame->length = pcap_length;
                    
                    frame_count++;
                    
                    // 检查是否收集满一批帧
                    if (frame_count == FRAME_BATCH_SIZE) {
                        process_frames(frame_batch, frame_count);
                        
                        // 释放帧内存并重置计数
                        for (int i = 0; i < frame_count; i++) {
                            free(frame_batch[i].data);
                        }
                        frame_count = 0;
                    }
                }
            }

            // 移动到下一个数据包
            current_offset += full_pkt_length;
        }

        // 移动剩余数据到缓冲区开头
        size_t remaining = total_bytes - current_offset;
        if (remaining > 0 && current_offset > 0) {
            memmove(buffer, buffer + current_offset, remaining);
        }
        data_offset = remaining;
    }

    // 处理剩余未满批次的帧
    if (frame_count > 0) {
        process_frames(frame_batch, frame_count);
        for (int i = 0; i < frame_count; i++) {
            free(frame_batch[i].data);
        }
    }

    // 清理资源
    close(client_fd);
    close(server_fd);
    return 0;
}