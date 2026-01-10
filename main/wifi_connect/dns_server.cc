#include "dns_server.h"
#include <esp_log.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>

#define TAG "DnsServer"

DnsServer::DnsServer() {
}

DnsServer::~DnsServer() {
    Stop();
}

void DnsServer::Start(esp_ip4_addr_t gateway) {
    // If already running, stop first
    if (running_) {
        Stop();
    }

    ESP_LOGI(TAG, "Starting DNS server");
    gateway_ = gateway;

    fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd_ < 0) {
        ESP_LOGE(TAG, "Failed to create socket");
        return;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port_);

    if (bind(fd_, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "failed to bind port %d", port_);
        close(fd_);
        fd_ = -1;
        return;
    }

    running_ = true;
    xTaskCreate([](void* arg) {
        DnsServer* dns_server = static_cast<DnsServer*>(arg);
        dns_server->Run();
        vTaskDelete(NULL);
    }, "DnsServerTask", 4096, this, 5, &task_handle_);
}

void DnsServer::Stop() {
    if (!running_) {
        return;
    }

    ESP_LOGI(TAG, "Stopping DNS server");
    running_ = false;

    // Close socket to unblock recvfrom
    if (fd_ >= 0) {
        shutdown(fd_, SHUT_RDWR);
        close(fd_);
        fd_ = -1;
    }

    // Wait for task to finish
    if (task_handle_ != nullptr) {
        // Give the task some time to exit gracefully
        vTaskDelay(pdMS_TO_TICKS(100));
        task_handle_ = nullptr;
    }
}

void DnsServer::Run() {
    char buffer[512];
    while (running_) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int len = recvfrom(fd_, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_addr_len);
        if (len < 0) {
            if (!running_) {
                // Socket was closed during Stop(), exit gracefully
                break;
            }
            ESP_LOGE(TAG, "recvfrom failed, errno=%d", errno);
            continue;
        }

        if (!running_) {
            break;
        }

        // Extract domain name from DNS query to check if it's a captive portal detection domain
        // DNS query format: header (12 bytes) + question section
        // We'll parse the domain name to check for captive portal detection domains
        char domain[256] = {0};
        int pos = 12;  // Skip DNS header
        int domain_pos = 0;

        while (pos < len && buffer[pos] != 0 && domain_pos < sizeof(domain) - 1) {
            int label_len = buffer[pos];
            if (label_len == 0 || label_len > 63 || pos + label_len >= len) break;

            if (domain_pos > 0) {
                domain[domain_pos++] = '.';
            }
            memcpy(domain + domain_pos, buffer + pos + 1, label_len);
            domain_pos += label_len;
            pos += label_len + 1;
        }
        domain[domain_pos] = '\0';

        // Check if this is a captive portal detection domain
        bool is_captive_portal_domain = false;
        const char* captive_portal_domains[] = {
            "connectivitycheck.gstatic.com",  // Android
            "clients3.google.com",             // Android
            "captive.apple.com",               // iOS/macOS
            "www.apple.com",                   // iOS/macOS
            "www.appleiphonecell.com",        // iOS
            "msftconnecttest.com",            // Windows
            "www.msftconnecttest.com",        // Windows
            "detectportal.firefox.com",       // Firefox
            NULL
        };

        for (int i = 0; captive_portal_domains[i] != NULL; i++) {
            if (strcasecmp(domain, captive_portal_domains[i]) == 0) {
                is_captive_portal_domain = true;
                ESP_LOGI(TAG, "Detected captive portal detection domain: %s", domain);
                break;
            }
        }

        // Only redirect non-captive-portal domains to our IP
        // For captive portal detection domains, we don't respond (let them fail or timeout)
        // This prevents the captive portal popup
        if (!is_captive_portal_domain) {
            // Simple DNS response: point query to 192.168.4.1
            buffer[2] |= 0x80;  // Set response flag
            buffer[3] |= 0x80;  // Set Recursion Available
            buffer[7] = 1;      // Set answer count to 1

            // Add answer section
            memcpy(&buffer[len], "\xc0\x0c", 2);  // Name pointer
            len += 2;
            memcpy(&buffer[len], "\x00\x01\x00\x01\x00\x00\x00\x1c\x00\x04", 10);  // Type, class, TTL, data length
            len += 10;
            memcpy(&buffer[len], &gateway_.addr, 4);  // 192.168.4.1
            len += 4;
            ESP_LOGI(TAG, "Sending DNS response for %s to %s", domain, inet_ntoa(gateway_.addr));

            sendto(fd_, buffer, len, 0, (struct sockaddr *)&client_addr, client_addr_len);
        } else {
            ESP_LOGI(TAG, "Ignoring captive portal detection domain: %s", domain);
        }
    }

    task_handle_ = nullptr;
    ESP_LOGI(TAG, "DNS server task exiting");
}
