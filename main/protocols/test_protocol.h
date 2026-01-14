#ifndef TEST_PROTOCOL_H
#define TEST_PROTOCOL_H

#include "protocol.h"
#include <http.h>
#include <cJSON.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <opus_decoder.h>
#include <opus_encoder.h>
#include "audio/mp3_decoder.h"

#include <functional>
#include <string>
#include <memory>
#include <atomic>
#include <mutex>

#define TEST_PROTOCOL_AUTH_INTERVAL_MS (30 * 60 * 1000)  // 30 minutes

class TestProtocol : public Protocol {
public:
    TestProtocol();
    ~TestProtocol();

    bool Start() override;
    bool SendAudio(std::unique_ptr<AudioStreamPacket> packet) override;
    bool OpenAudioChannel() override;
    void CloseAudioChannel() override;
    bool IsAudioChannelOpened() const override;

private:
    // Alive flag for safe scheduled callbacks
    std::shared_ptr<std::atomic<bool>> alive_ = std::make_shared<std::atomic<bool>>(true);

    EventGroupHandle_t event_group_handle_;
    std::mutex auth_mutex_;
    std::string auth_token_;
    esp_timer_handle_t auth_timer_;
    bool authenticated_ = false;
    bool audio_channel_opened_ = false;

    // Audio accumulation buffer (stores decoded PCM int16 samples)
    std::mutex audio_buffer_mutex_;
    std::vector<int16_t> accumulated_audio_;

    // Opus decoder for converting incoming Opus packets to PCM
    std::unique_ptr<OpusDecoderWrapper> opus_decoder_;

    // MP3 decoder and Opus encoder for TTS response conversion
    std::unique_ptr<Mp3Decoder> mp3_decoder_;
    std::unique_ptr<OpusEncoderWrapper> opus_encoder_;

    // Audio processing thread
    TaskHandle_t audio_processing_thread_ = nullptr;
    std::atomic<bool> audio_processing_running_{false};

    // Lock to prevent audio accumulation during TTS processing
    std::atomic<bool> tts_in_progress_{false};

    // API Configuration
    static constexpr const char* API_BASE_URL = "http://openwebui-lb-788839738.ap-southeast-1.elb.amazonaws.com/api/v1";
    static constexpr const char* AUTH_EMAIL = "tungch@gmail.com";
    static constexpr const char* AUTH_PASSWORD = "123456a@";
    static constexpr const char* TTS_VOICE_ID = "3fTZRfeclSMoZMOrSplv";

    // Private methods
    bool Authenticate();
    bool SendSTTRequest(const std::vector<int16_t>& audio_data, std::string& transcription);
    bool SendChatRequest(const std::string& message, std::string& response);
    bool SendTTSRequest(const std::string& text, std::vector<uint8_t>& audio_data);
    bool SendText(const std::string& text) override;
    void ProcessAudioFlow();
    void PlayAudioResponse(const std::vector<uint8_t>& audio_data);
    void StartAudioProcessingThread();
    void StopAudioProcessingThread();
    static void AudioProcessingTask(void* arg);

    // Helper for HTTP requests
    std::unique_ptr<Http> CreateHttpClient();

    // Convert MP3 audio to Opus-encoded packets
    bool ConvertMp3ToOpus(const std::vector<uint8_t>& mp3_data, std::vector<uint8_t>& opus_data);
};

#endif // TEST_PROTOCOL_H
