#include <iostream>
#include <vector>
#include <memory>
#include <cstring>
#include <cstdint>
#include <stdexcept>
#include <system_error>
#include <functional>
#include <algorithm>

#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

// 常量定义
constexpr size_t HEADER_SIZE = 40;
constexpr size_t RESERVED_SIZE = 40;
constexpr size_t PCAP_HEADER_SIZE = 24;
constexpr size_t COMMON_HEAD_SIZE = 12;
constexpr size_t MAX_FRAMES_PER_BIG = 64;
constexpr size_t RECV_BUFFER_SIZE = 65536;
constexpr uint32_t PCAP_MAGIC_BIG_ENDIAN = 0xA1B2C3D4;
constexpr uint32_t PCAP_MAGIC_LITTLE_ENDIAN = 0xD4C3B2A1;

// 通用包头结构 (使用 pragma pack 确保字节对齐)
#pragma pack(push, 1)
struct CommonHead {
    uint32_t packetlen;  // 当前帧数据长度
    uint32_t totallen;   // 当前包总长度（包括包头）
    uint32_t seqnum;     // 序列号（大包中表示小包数量）
    uint8_t data[0];     // 柔性数组

    // 转换为主机字节序
    void to_host() {
        packetlen = ntohl(packetlen);
        totallen = ntohl(totallen);
        seqnum = ntohl(seqnum);
    }

    // 转换为网络字节序
    void to_network() {
        packetlen = htonl(packetlen);
        totallen = htonl(totallen);
        seqnum = htonl(seqnum);
    }
};
#pragma pack(pop)

// 使用 unique_ptr 的删除器释放内存
struct FreeDeleter {
    void operator()(void* p) const { free(p); }
};
using CommonHeadPtr = std::unique_ptr<CommonHead, FreeDeleter>;

// 动态缓冲区封装类
class DynamicBuffer {
public:
    DynamicBuffer(size_t initial_size = RECV_BUFFER_SIZE)
        : buffer_(initial_size), size_(0) {}

    // 追加数据到缓冲区
    void append(const uint8_t* data, size_t len) {
        if (size_ + len > buffer_.size()) {
            buffer_.resize(std::max(buffer_.size() * 2, size_ + len));
        }
        std::memcpy(buffer_.data() + size_, data, len);
        size_ += len;
    }

    // 从缓冲区消费数据
    void consume(size_t len) {
        if (len > size_) len = size_;
        if (len < size_) {
            std::memmove(buffer_.data(), buffer_.data() + len, size_ - len);
        }
        size_ -= len;
    }

    // 获取缓冲区指针
    uint8_t* data() { return buffer_.data(); }
    const uint8_t* data() const { return buffer_.data(); }

    // 获取当前数据长度
    size_t size() const { return size_; }

    // 清空缓冲区
    void clear() { size_ = 0; }

private:
    std::vector<uint8_t> buffer_;
    size_t size_;
};

// TCP 服务器封装类
class TCPServer {
public:
    TCPServer(int port) : port_(port), server_fd_(-1) {}
    
    ~TCPServer() {
        if (server_fd_ != -1) {
            close(server_fd_);
        }
    }

    // 设置并启动服务器
    void setup() {
        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd_ < 0) {
            throw std::system_error(errno, std::system_category(), "socket failed");
        }

        int opt = 1;
        if (setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            throw std::system_error(errno, std::system_category(), "setsockopt");
        }

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port_);

        if (bind(server_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
            throw std::system_error(errno, std::system_category(), "bind failed");
        }

        if (listen(server_fd_, 10) < 0) {
            throw std::system_error(errno, std::system_category(), "listen");
        }

        std::cout << "Server listening on port " << port_ << std::endl;
    }

    // 接受客户端连接
    int accept_client() {
        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_fd_, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
        if (client_sock < 0) {
            throw std::system_error(errno, std::system_category(), "accept");
        }

        std::cout << "Client connected from " 
                  << inet_ntoa(client_addr.sin_addr) << ":" 
                  << ntohs(client_addr.sin_port) << std::endl;
        return client_sock;
    }

private:
    int port_;
    int server_fd_;
};

// 创建小包
CommonHeadPtr create_small_packet(const uint8_t* pcap_data, uint32_t data_len) {
    const uint32_t total_size = COMMON_HEAD_SIZE + data_len;
    auto* packet = static_cast<CommonHead*>(std::malloc(total_size));
    if (!packet) {
        throw std::bad_alloc();
    }

    // 设置包头字段（主机字节序）
    packet->packetlen = data_len;
    packet->totallen = total_size;
    packet->seqnum = 0;
    
    // 复制数据
    std::memcpy(packet->data, pcap_data, data_len);
    
    // 转换为网络字节序
    packet->to_network();
    
    return CommonHeadPtr(packet);
}

// 创建大包（包含多个小包）
CommonHeadPtr create_big_packet(std::vector<CommonHeadPtr>& small_packets) {
    // 计算大包总长度
    uint32_t total_data_size = 0;
    for (auto& pkt : small_packets) {
        pkt->to_host(); // 转换为本地字节序以读取长度
        total_data_size += pkt->totallen;
        pkt->to_network(); // 转换回网络字节序
    }
    
    const uint32_t big_total_size = COMMON_HEAD_SIZE + total_data_size;
    auto* big_packet = static_cast<CommonHead*>(std::malloc(big_total_size));
    if (!big_packet) {
        throw std::bad_alloc();
    }
    
    // 设置大包头字段（主机字节序）
    big_packet->packetlen = total_data_size;
    big_packet->totallen = big_total_size;
    big_packet->seqnum = static_cast<uint32_t>(small_packets.size());
    
    // 转换为网络字节序
    big_packet->to_network();
    
    // 复制所有小包数据
    uint8_t* pos = big_packet->data;
    for (auto& pkt : small_packets) {
        pkt->to_host(); // 转换为本地字节序以读取长度
        const uint32_t small_size = pkt->totallen;
        std::memcpy(pos, pkt.get(), small_size);
        pos += small_size;
        pkt->to_network(); // 转换回网络字节序
    }
    
    return CommonHeadPtr(big_packet);
}

// 验证PCAP魔术字
bool validate_pcap_magic(const uint8_t* data) {
    uint32_t magic;
    std::memcpy(&magic, data, sizeof(magic));
    return (magic == PCAP_MAGIC_BIG_ENDIAN || 
            magic == PCAP_MAGIC_LITTLE_ENDIAN);
}

// 处理接收到的数据包
void process_packet(DynamicBuffer& recv_buf, 
                   std::vector<CommonHeadPtr>& frame_list,
                   const std::function<void(CommonHead*)>& send_big_packet) {
    while (recv_buf.size() >= 4) {
        // 解析包长度
        uint32_t packet_len;
        std::memcpy(&packet_len, recv_buf.data(), sizeof(packet_len));
        packet_len = ntohl(packet_len);
        const uint32_t total_packet_size = packet_len + 4; // 包含4字节长度字段

        // 检查是否收到完整包
        if (recv_buf.size() < total_packet_size) break;

        // 验证最小包长度
        if (total_packet_size < HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE) {
            std::cerr << "Packet too small: " << total_packet_size 
                      << " bytes, skipping\n";
            recv_buf.consume(total_packet_size);
            continue;
        }

        // 计算魔术字位置
        const uint8_t* pcap_header = recv_buf.data() + HEADER_SIZE + RESERVED_SIZE;
        
        // 验证PCAP魔术字
        if (!validate_pcap_magic(pcap_header)) {
            uint32_t magic;
            std::memcpy(&magic, pcap_header, sizeof(magic));
            std::cerr << "Invalid PCAP magic: 0x" << std::hex << magic 
                      << ", skipping packet\n";
            recv_buf.consume(total_packet_size);
            continue;
        }

        // 计算PCAP数据位置
        const uint32_t pcap_data_offset = HEADER_SIZE + RESERVED_SIZE + PCAP_HEADER_SIZE;
        const uint32_t pcap_data_len = total_packet_size - pcap_data_offset;

        // 检查PCAP数据长度
        if (pcap_data_len == 0) {
            std::cerr << "Zero-length PCAP data, skipping\n";
            recv_buf.consume(total_packet_size);
            continue;
        }

        // 创建小包
        try {
            auto small_pkt = create_small_packet(
                recv_buf.data() + pcap_data_offset, 
                pcap_data_len
            );
            
            // 添加到帧列表
            if (frame_list.size() < MAX_FRAMES_PER_BIG) {
                frame_list.push_back(std::move(small_pkt));
            } else {
                std::cerr << "Frame list full, discarding packet\n";
            }
        } catch (const std::bad_alloc&) {
            std::cerr << "Memory allocation failed for small packet\n";
            recv_buf.consume(total_packet_size);
            continue;
        }

        // 如果收集到足够帧数，发送大包
        if (frame_list.size() == MAX_FRAMES_PER_BIG) {
            try {
                auto big_packet = create_big_packet(frame_list);
                send_big_packet(big_packet.get());
                frame_list.clear();
            } catch (const std::bad_alloc&) {
                std::cerr << "Memory allocation failed for big packet\n";
                frame_list.clear();
            }
        }

        // 从缓冲区移除已处理数据
        recv_buf.consume(total_packet_size);
    }
}

// 处理剩余帧
void flush_remaining_frames(std::vector<CommonHeadPtr>& frame_list, 
                           const std::function<void(CommonHead*)>& send_big_packet) {
    if (frame_list.empty()) return;
    
    std::cout << "Sending partial packet with " 
              << frame_list.size() << " frames\n";
    
    try {
        auto big_packet = create_big_packet(frame_list);
        send_big_packet(big_packet.get());
    } catch (const std::bad_alloc&) {
        std::cerr << "Memory allocation failed for partial big packet\n";
    }
    frame_list.clear();
}

// 示例发送函数
void example_send_big_packet(CommonHead* big_packet) {
    // 临时转换为本地字节序以便读取
    CommonHead tmp;
    std::memcpy(&tmp, big_packet, sizeof(CommonHead));
    tmp.to_host();
    
    std::cout << "Sending big packet: seqnum=" << tmp.seqnum
              << ", packetlen=" << tmp.packetlen
              << ", totallen=" << tmp.totallen << "\n";
    
    // 实际应用中这里应发送数据
}

int main(int argc, char* argv[]) {
    const int port = 8080;
    
    try {
        TCPServer server(port);
        server.setup();
        
        DynamicBuffer recv_buf;
        std::vector<CommonHeadPtr> frame_list;
        frame_list.reserve(MAX_FRAMES_PER_BIG);

        while (true) {
            int client_sock = server.accept_client();
            
            uint8_t temp_buf[4096];
            while (true) {
                ssize_t n = recv(client_sock, temp_buf, sizeof(temp_buf), 0);
                if (n <= 0) {
                    if (n == 0) {
                        std::cout << "Client disconnected\n";
                    } else {
                        std::cerr << "recv failed: " << strerror(errno) << "\n";
                    }
                    break;
                }
                
                // 添加到接收缓冲区
                recv_buf.append(temp_buf, static_cast<size_t>(n));
                
                // 处理缓冲区中的数据
                process_packet(recv_buf, frame_list, example_send_big_packet);
            }
            
            // 处理剩余未满64帧的数据
            flush_remaining_frames(frame_list, example_send_big_packet);
            recv_buf.clear();
            
            close(client_sock);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}