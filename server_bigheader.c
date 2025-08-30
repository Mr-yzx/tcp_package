#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>

#define HEADER_SIZE 40
#define RESERVED_SIZE 40
#define PCAP_HEADER_SIZE 24
#define SMALL_HEADER_SIZE 300
#define BIG_HEADER_SIZE 300
#define MAX_FRAMES_PER_BIG 64
#define RECV_BUFFER_SIZE 65536

// 大包头结构
typedef struct {
    uint32_t count;     // 包含的小包数量
    uint32_t totallen;  // 大包总长度（包含包头）
    uint8_t reserved[BIG_HEADER_SIZE - 8]; // 保留字段
} BigHeader;

// 小包头结构
typedef struct {
    uint8_t data[SMALL_HEADER_SIZE]; // 全部保留字段
} SmallHeader;

// 小包结构（包头 + 数据）
typedef struct {
    SmallHeader header;
    uint8_t* pcap_data;
    uint32_t data_len;
} SmallPacket;

// 全局缓冲区管理
typedef struct {
    uint8_t* buffer;
    size_t size;
    size_t len;
} Buffer;

Buffer* create_buffer(size_t initial_size) {
    Buffer* buf = malloc(sizeof(Buffer));
    buf->buffer = malloc(initial_size);
    buf->size = initial_size;
    buf->len = 0;
    return buf;
}

void append_to_buffer(Buffer* buf, const uint8_t* data, size_t len) {
    if (buf->len + len > buf->size) {
        size_t new_size = buf->size * 2;
        while (buf->len + len > new_size) new_size *= 2;
        buf->buffer = realloc(buf->buffer, new_size);
        buf->size = new_size;
    }
    memcpy(buf->buffer + buf->len, data, len);
    buf->len += len;
}

void consume_buffer(Buffer* buf, size_t len) {
    if (len > buf->len) len = buf->len;
    memmove(buf->buffer, buf->buffer + len, buf->len - len);
    buf->len -= len;
}

void free_buffer(Buffer* buf) {
    free(buf->buffer);
    free(buf);
}

// TCP服务器初始化
int setup_tcp_server(int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port)
    };

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return server_fd;
}

// 处理接收到的数据包
void process_packet(Buffer* recv_buf, SmallPacket* frame_list, int* frame_count, void (*send_big_packet)(uint8_t*, size_t)) {
    while (recv_buf->len >= 4) {
        // 解析包长度 (小端序)
        uint32_t packet_len = *(uint32_t*)recv_buf->buffer;
        packet_len = ntohl(packet_len);
        uint32_t total_packet_size = packet_len + 4; // 包含4字节长度字段

        // 检查是否收到完整包
        if (recv_buf->len < total_packet_size) break;

        // 计算PCAP数据位置和长度
        uint32_t pcap_data_offset = 4 + HEADER_SIZE - 4 + RESERVED_SIZE + PCAP_HEADER_SIZE;
        uint32_t pcap_data_len = total_packet_size - pcap_data_offset;

        // 验证数据有效性
        if (pcap_data_offset > total_packet_size || pcap_data_len == 0) {
            fprintf(stderr, "Invalid packet structure\n");
            consume_buffer(recv_buf, total_packet_size);
            continue;
        }

        // 创建小包
        SmallPacket small_pkt;
        small_pkt.data_len = pcap_data_len;
        printf("pcap_data_len: %d\n", pcap_data_len);
        small_pkt.pcap_data = malloc(pcap_data_len);
        if (!small_pkt.pcap_data) {
            perror("malloc failed");
            consume_buffer(recv_buf, total_packet_size);
            continue;
        }

        // 复制PCAP数据
        memcpy(small_pkt.pcap_data, recv_buf->buffer + pcap_data_offset, pcap_data_len);
        memset(&small_pkt.header, 0, SMALL_HEADER_SIZE); // 清包头

        // 添加到帧列表
        frame_list[*frame_count] = small_pkt;
        (*frame_count)++;

        // 如果收集到足够帧数，发送大包
        if (*frame_count == MAX_FRAMES_PER_BIG) {
            // 计算总长度
            uint32_t total_data_len = 0;
            for (int i = 0; i < MAX_FRAMES_PER_BIG; i++) {
                total_data_len += SMALL_HEADER_SIZE + frame_list[i].data_len;
            }
            
            uint32_t big_packet_size = BIG_HEADER_SIZE + total_data_len;
            uint8_t* big_packet = malloc(big_packet_size);
            if (!big_packet) {
                perror("malloc failed for big packet");
                continue;
            }

            // 设置大包头
            BigHeader* bh = (BigHeader*)big_packet;
            bh->count = htonl(MAX_FRAMES_PER_BIG);
            bh->totallen = htonl(big_packet_size);
            memset(bh->reserved, 0, sizeof(bh->reserved));

            // 复制所有小包数据
            uint8_t* pos = big_packet + BIG_HEADER_SIZE;
            for (int i = 0; i < MAX_FRAMES_PER_BIG; i++) {
                SmallPacket* sp = &frame_list[i];
                memcpy(pos, &sp->header, SMALL_HEADER_SIZE);
                pos += SMALL_HEADER_SIZE;
                memcpy(pos, sp->pcap_data, sp->data_len);
                pos += sp->data_len;
            }

            // 发送大包
            send_big_packet(big_packet, big_packet_size);
            
            // 清理资源
            for (int i = 0; i < MAX_FRAMES_PER_BIG; i++) {
                free(frame_list[i].pcap_data);
            }
            free(big_packet);
            *frame_count = 0;
        }

        // 从缓冲区移除已处理数据
        consume_buffer(recv_buf, total_packet_size);
    }
}

// 示例发送函数 (需根据实际情况实现)
void example_send_big_packet(uint8_t* data, size_t len) {
    printf("Sending big packet: %zu bytes\n", len);
    // 实际发送代码 (如 write/send 或 保存到文件)
    // free(data); // 这里直接释放，实际使用中应在发送完成后释放
}

int main(int argc, char* argv[]) {
    // if (argc != 2) {
    //     fprintf(stderr, "Usage: %s <port>\n", argv[0]);
    //     exit(EXIT_FAILURE);
    // }

    int port = 8080;
    int server_fd = setup_tcp_server(port);

    printf("Server listening on port %d\n", port);

    Buffer* recv_buf = create_buffer(RECV_BUFFER_SIZE);
    SmallPacket frame_list[MAX_FRAMES_PER_BIG];
    int frame_count = 0;

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }

        printf("Client connected\n");

        uint8_t temp_buf[4096];
        while (1) {
            ssize_t n = recv(client_sock, temp_buf, sizeof(temp_buf), 0);
            if (n <= 0) {
                if (n == 0) printf("Client disconnected\n");
                else perror("recv failed");
                break;
            }

            // 添加到接收缓冲区
            append_to_buffer(recv_buf, temp_buf, n);

            // 处理缓冲区中的数据
            process_packet(recv_buf, frame_list, &frame_count, example_send_big_packet);
        }

        close(client_sock);
        
        // 处理剩余未满64帧的数据
        if (frame_count > 0) {
            printf("Sending partial packet with %d frames\n", frame_count);
            
            // 计算总长度
            uint32_t total_data_len = 0;
            for (int i = 0; i < frame_count; i++) {
                total_data_len += SMALL_HEADER_SIZE + frame_list[i].data_len;
            }
            
            uint32_t big_packet_size = BIG_HEADER_SIZE + total_data_len;
            uint8_t* big_packet = malloc(big_packet_size);
            
            // 设置大包头
            BigHeader* bh = (BigHeader*)big_packet;
            bh->count = htonl(frame_count);
            bh->totallen = htonl(big_packet_size);
            memset(bh->reserved, 0, sizeof(bh->reserved));

            // 复制所有小包数据
            uint8_t* pos = big_packet + BIG_HEADER_SIZE;
            for (int i = 0; i < frame_count; i++) {
                SmallPacket* sp = &frame_list[i];
                memcpy(pos, &sp->header, SMALL_HEADER_SIZE);
                pos += SMALL_HEADER_SIZE;
                memcpy(pos, sp->pcap_data, sp->data_len);
                pos += sp->data_len;
                free(sp->pcap_data);
            }
            
            example_send_big_packet(big_packet, big_packet_size);
            frame_count = 0;
        }
    }

    close(server_fd);
    free_buffer(recv_buf);
    return 0;
}