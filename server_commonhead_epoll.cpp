#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#define HEADER_SIZE 40
#define RESERVED_SIZE 40
#define PCAP_HEADER_SIZE 24
#define COMMON_HEAD_SIZE 12
#define MAX_FRAMES_PER_BIG 64
#define RECV_BUFFER_SIZE 65536
#define PCAP_MAGIC_BIG_ENDIAN 0xA1B2C3D4
#define PCAP_MAGIC_LITTLE_ENDIAN 0xD4C3B2A1
#define MAX_EVENTS 1024
#define EPOLL_TIMEOUT 10000

// 通用包头结构
#pragma pack(push, 1)
typedef struct {
    uint32_t packetlen;
    uint32_t totallen;
    uint32_t seqnum;
    uint8_t data[];
} CommonHead;
// 全局缓冲区管理
typedef struct {
    uint8_t* buffer;
    size_t size;
    size_t len;
} Buffer;

// 客户端上下文结构
typedef struct {
    int sockfd;
    struct sockaddr_in addr;
    Buffer* recv_buf;
    CommonHead* frame_list[MAX_FRAMES_PER_BIG];
    int frame_count;
} ClientContext;


#pragma pack(pop)

int append_to_file(const char* filename, const void* data, size_t data_len) {
    // 参数检查
    if (!filename || !data || data_len == 0) {
        errno = EINVAL;
        return -1;
    }

    // 打开文件（追加模式，不存在则创建）
    int fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        return -1;  // 失败时保留系统错误码
    }

    size_t total_written = 0;
    const char* buf = (const char*)data;

    // 循环写入确保处理所有数据
    while (total_written < data_len) {
        ssize_t n = write(fd, buf + total_written, data_len - total_written);
        if (n < 0) {
            if (errno == EINTR) continue;  // 被信号中断则重试
            close(fd);
            return -1;
        }
        total_written += n;
    }

    // 关闭文件描述符
    if (close(fd) < 0) {
        return -1;
    }

    return 0;  // 成功返回0
}

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

// 设置非阻塞模式
int set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
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

    // 设置服务器套接字为非阻塞
    if (set_nonblocking(server_fd) < 0) {
        perror("set_nonblocking failed");
        close(server_fd);
        return -1;
    }

    return server_fd;
}

// 验证PCAP魔术字
int validate_pcap_magic(const uint8_t* data) {
    uint32_t magic = *(const uint32_t*)data;
    printf("magic=%x\n", magic);
    return (magic == PCAP_MAGIC_BIG_ENDIAN || 
            magic == PCAP_MAGIC_LITTLE_ENDIAN);
}

// 创建小包
CommonHead* create_small_packet(const uint8_t* pcap_data, uint32_t data_len) {
    
    uint32_t total_size = COMMON_HEAD_SIZE + data_len;
    CommonHead* packet = (CommonHead*)malloc(total_size);
    if (!packet) return NULL;
    
    packet->packetlen = data_len;
    packet->totallen = total_size;
    packet->seqnum = 0;
    
    memcpy(packet->data, pcap_data, data_len);
    printf("packet->packetlen=%d\n", packet->packetlen);
    printf("smallpacket->totallen=%d\n", packet->totallen);
    // packet->packetlen = htonl(packet->packetlen);
    // packet->totallen = htonl(packet->totallen);
    // packet->seqnum = htonl(packet->seqnum);
    
    return packet;
}

// 创建大包
CommonHead* create_big_packet(CommonHead** small_packets, int count) {
    uint32_t total_data_size = 0;
    for (int i = 0; i < count; i++) {
        // total_data_size += ntohl(small_packets[i]->totallen);
        total_data_size += small_packets[i]->totallen;
    }
    
    uint32_t big_total_size = COMMON_HEAD_SIZE + total_data_size;
    CommonHead* big_packet = (CommonHead *)malloc(big_total_size);
    if (!big_packet) return NULL;
    
    big_packet->packetlen = total_data_size;
    big_packet->totallen = big_total_size;
    big_packet->seqnum = count;
    
    // big_packet->packetlen = htonl(big_packet->packetlen);
    // big_packet->totallen = htonl(big_packet->totallen);
    // big_packet->seqnum = htonl(big_packet->seqnum);
    
    uint8_t* pos = big_packet->data;
    for (int i = 0; i < count; i++) {
        // uint32_t small_size = ntohl(small_packets[i]->totallen);
        uint32_t small_size = small_packets[i]->totallen;
        memcpy(pos, small_packets[i], small_size);
        pos += small_size;
        free(small_packets[i]);
    }
    
    return big_packet;
}

// 处理接收到的数据包
void process_packet(Buffer* recv_buf, CommonHead** frame_list, int* frame_count, 
                   void (*send_big_packet)(CommonHead*)) {
    while (recv_buf->len >= 4) {
        uint32_t packet_len = *(uint32_t*)recv_buf->buffer;
        packet_len = ntohl(packet_len);
        uint32_t total_packet_size = packet_len + 4;

        if (recv_buf->len < total_packet_size) break;

        if (total_packet_size < HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE) {
            fprintf(stderr, "Packet too small: %u bytes, skipping\n", total_packet_size);
            consume_buffer(recv_buf, total_packet_size);
            continue;
        }

        const uint8_t* pcap_header = recv_buf->buffer + HEADER_SIZE + RESERVED_SIZE;
        uint32_t lingtype = *(uint32_t *)(pcap_header + 20);
        printf("linktype=%d\n", lingtype);
        if (!validate_pcap_magic(pcap_header)) {
            fprintf(stderr, "Invalid PCAP magic: 0x%08X, skipping packet\n", *(uint32_t*)pcap_header);
            consume_buffer(recv_buf, total_packet_size);
            continue;
        }

        uint32_t pcap_data_offset = HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE;
        uint32_t pcap_data_len = total_packet_size - pcap_data_offset;

        if (pcap_data_len == 0) {
            fprintf(stderr, "Zero-length PCAP data, skipping\n");
            consume_buffer(recv_buf, total_packet_size);
            continue;
        }

        CommonHead* small_pkt = create_small_packet(
            recv_buf->buffer + pcap_data_offset, 
            pcap_data_len
        );
        
        if (!small_pkt) {
            perror("Failed to create small packet");
            consume_buffer(recv_buf, total_packet_size);
            continue;
        }

        if (*frame_count < MAX_FRAMES_PER_BIG) {
            frame_list[*frame_count] = small_pkt;
            (*frame_count)++;
        } else {
            fprintf(stderr, "Frame list full, discarding packet\n");
            free(small_pkt);
        }

        if (*frame_count == MAX_FRAMES_PER_BIG) {
            CommonHead* big_packet = create_big_packet(frame_list, *frame_count);
            if (big_packet) {
                send_big_packet(big_packet);
            } else {
                perror("Failed to create big packet");
                for (int i = 0; i < *frame_count; i++) {
                    free(frame_list[i]);
                }
            }
            *frame_count = 0;
        }

        consume_buffer(recv_buf, total_packet_size);
    }
}

// 示例发送函数
void example_send_big_packet(CommonHead* big_packet) {
    // uint32_t packetlen = ntohl(big_packet->packetlen);
    // uint32_t totallen = ntohl(big_packet->totallen);
    // uint32_t seqnum = ntohl(big_packet->seqnum);

    uint32_t packetlen = big_packet->packetlen;
    uint32_t totallen =big_packet->totallen;
    uint32_t seqnum = big_packet->seqnum;
    
    printf("Sending big packet: seqnum=%u, packetlen=%u, totallen=%u\n", 
           seqnum, packetlen, totallen);
    
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
        for (int i = 0; i < frame_count; i++) {
            free(frame_list[i]);
        }
    }
}

// 清理客户端资源
void cleanup_client(ClientContext* client) {
    if (!client) return;
    
    flush_remaining_frames(client->frame_list, client->frame_count, example_send_big_packet);
    if (client->recv_buf) free_buffer(client->recv_buf);
    close(client->sockfd);
    free(client);
}

int main(int argc, char* argv[]) {
    int port = 8080;
    int server_fd = setup_tcp_server(port);
    if (server_fd < 0) {
        return EXIT_FAILURE;
    }

    printf("Server listening on port %d\n", port);

    // 创建epoll实例
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1 failed");
        close(server_fd);
        return EXIT_FAILURE;
    }

    // 添加服务器套接字到epoll
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1) {
        perror("epoll_ctl server failed");
        close(server_fd);
        close(epoll_fd);
        return EXIT_FAILURE;
    }

    struct epoll_event events[MAX_EVENTS];
    
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, EPOLL_TIMEOUT);
        if (nfds == -1) {
            perror("epoll_wait failed");
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_fd) {
                // 处理新连接
                while (1) {
                    struct sockaddr_in client_addr;
                    socklen_t addr_len = sizeof(client_addr);
                    int client_sock = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
                    if (client_sock == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break; // 所有连接已处理
                        }
                        perror("accept failed");
                        break;
                    }

                    // 设置客户端套接字为非阻塞
                    if (set_nonblocking(client_sock) < 0) {
                        perror("set_nonblocking client failed");
                        close(client_sock);
                        continue;
                    }

                    // 创建客户端上下文
                    ClientContext* client = (ClientContext*)malloc(sizeof(ClientContext));
                    if (!client) {
                        perror("malloc client context failed");
                        close(client_sock);
                        continue;
                    }
                    
                    client->sockfd = client_sock;
                    client->addr = client_addr;
                    client->recv_buf = create_buffer(RECV_BUFFER_SIZE);
                    client->frame_count = 0;
                    
                    if (!client->recv_buf) {
                        perror("create_buffer failed");
                        free(client);
                        close(client_sock);
                        continue;
                    }

                    printf("Client connected from %s:%d\n", 
                           inet_ntoa(client_addr.sin_addr), 
                           ntohs(client_addr.sin_port));

                    // 添加客户端到epoll
                    ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLHUP;
                    ev.data.ptr = client;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_sock, &ev) == -1) {
                        perror("epoll_ctl client failed");
                        cleanup_client(client);
                    }
                }
            } else {
                // 处理客户端事件
                ClientContext* client = (ClientContext*)events[i].data.ptr;
                int client_sock = client->sockfd;
                
                // 检查连接关闭
                if (events[i].events & (EPOLLRDHUP | EPOLLHUP)) {
                    printf("Client disconnected\n");
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_sock, NULL);
                    cleanup_client(client);
                    continue;
                }
                
                // 处理数据接收
                if (events[i].events & EPOLLIN) {
                    uint8_t temp_buf[4096];
                    ssize_t total_read = 0;
                    
                    // ET模式：循环读取直到缓冲区为空
                    while (1) {
                        ssize_t n = recv(client_sock, temp_buf, sizeof(temp_buf), 0);
                        if (n == -1) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                break; // 数据读取完毕
                            }
                            perror("recv failed");
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_sock, NULL);
                            cleanup_client(client);
                            break;
                        } else if (n == 0) {
                            printf("Client disconnected\n");
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_sock, NULL);
                            cleanup_client(client);
                            break;
                        }
                        
                        // 添加到接收缓冲区
                        append_to_buffer(client->recv_buf, temp_buf, n);
                        // append_to_file("./recv.txt", temp_buf, n);
                        total_read += n;
                    }
                    
                    // 处理接收到的数据
                    if (total_read > 0) {
                        process_packet(client->recv_buf, client->frame_list, &client->frame_count, 
                                      example_send_big_packet);
                    }
                }
            }
        }
    }

    close(server_fd);
    close(epoll_fd);
    return EXIT_SUCCESS;
}