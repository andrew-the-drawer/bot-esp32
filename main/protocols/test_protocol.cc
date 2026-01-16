#include "test_protocol.h"
#include "board.h"
#include "application.h"
#include "assets/lang_config.h"

#include <esp_log.h>
#include <cstring>
#include <sstream>
#include <esp_mp3_dec.h>

#define TAG "TestProtocol"

TestProtocol::TestProtocol() {
    event_group_handle_ = xEventGroupCreate();

    // Initialize Opus decoder for 16kHz mono audio with 60ms frame duration
    opus_decoder_ = std::make_unique<OpusDecoderWrapper>(16000, 1, 60);

    // Initialize authentication timer to re-authenticate every 30 minutes
    esp_timer_create_args_t auth_timer_args = {
        .callback = [](void* arg) {
            TestProtocol* protocol = (TestProtocol*)arg;
            auto alive = protocol->alive_;
            Application::GetInstance().Schedule([protocol, alive]() {
                if (*alive) {
                    ESP_LOGI(TAG, "Re-authenticating (30 minute timer)");
                    protocol->Authenticate();
                }
            });
        },
        .arg = this,
    };
    esp_timer_create(&auth_timer_args, &auth_timer_);
}

TestProtocol::~TestProtocol() {
    ESP_LOGI(TAG, "TestProtocol deinit");

    // Mark as dead first to prevent any pending scheduled tasks from executing
    *alive_ = false;

    // Stop audio processing thread
    StopAudioProcessingThread();

    if (auth_timer_ != nullptr) {
        esp_timer_stop(auth_timer_);
        esp_timer_delete(auth_timer_);
    }

    if (event_group_handle_ != nullptr) {
        vEventGroupDelete(event_group_handle_);
    }
}

bool TestProtocol::Start() {
    ESP_LOGI(TAG, "Starting TestProtocol");

    // Authenticate on start
    if (!Authenticate()) {
        ESP_LOGE(TAG, "Initial authentication failed");
        SetError(Lang::Strings::SERVER_NOT_CONNECTED);
        return false;
    }

    // Start the 30-minute re-authentication timer
    esp_timer_start_periodic(auth_timer_, TEST_PROTOCOL_AUTH_INTERVAL_MS * 1000);

    if (on_connected_ != nullptr) {
        on_connected_();
    }

    ESP_LOGI(TAG, "TestProtocol started successfully");
    return true;
}

bool TestProtocol::Authenticate() {
    std::lock_guard<std::mutex> lock(auth_mutex_);

    ESP_LOGI(TAG, "Authenticating with email: %s", AUTH_EMAIL);

    auto http = CreateHttpClient();
    if (!http) {
        ESP_LOGE(TAG, "Failed to create HTTP client for authentication");
        return false;
    }

    // Build authentication URL
    std::string auth_url = std::string(API_BASE_URL) + "/auths/signin";

    // Build JSON payload
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "email", AUTH_EMAIL);
    cJSON_AddStringToObject(root, "password", AUTH_PASSWORD);
    char* json_str = cJSON_PrintUnformatted(root);
    std::string payload(json_str);
    cJSON_free(json_str);
    cJSON_Delete(root);

    // Set headers
    http->SetHeader("Content-Type", "application/json");
    http->SetContent(std::move(payload));

    // Send POST request
    if (!http->Open("POST", auth_url)) {
        ESP_LOGE(TAG, "Failed to open authentication request");
        return false;
    }

    // Check response status
    int status_code = http->GetStatusCode();
    if (status_code != 200) {
        std::string error_response = http->ReadAll();
        ESP_LOGE(TAG, "Authentication failed with status code: %d, response: %s", status_code, error_response.c_str());
        http->Close();
        return false;
    }

    // Read response body
    std::string response = http->ReadAll();
    http->Close();

    // Parse response to get token
    cJSON* response_json = cJSON_Parse(response.c_str());
    if (!response_json) {
        ESP_LOGE(TAG, "Failed to parse authentication response");
        return false;
    }

    cJSON* token_obj = cJSON_GetObjectItem(response_json, "token");
    if (!cJSON_IsString(token_obj)) {
        ESP_LOGE(TAG, "Token not found in authentication response");
        cJSON_Delete(response_json);
        return false;
    }

    auth_token_ = token_obj->valuestring;
    authenticated_ = true;

    ESP_LOGI(TAG, "Authentication successful, token: %.20s...", auth_token_.c_str());

    cJSON_Delete(response_json);
    return true;
}

bool TestProtocol::SendSTTRequest(const std::vector<int16_t>& audio_data, std::string& transcription) {
    if (!authenticated_) {
        ESP_LOGE(TAG, "Not authenticated");
        return false;
    }

    ESP_LOGI(TAG, "Sending STT request with %d samples (%d bytes) of audio",
             audio_data.size(), audio_data.size() * sizeof(int16_t));

    auto http = CreateHttpClient();
    if (!http) {
        ESP_LOGE(TAG, "Failed to create HTTP client for STT");
        return false;
    }

    std::string stt_url = std::string(API_BASE_URL) + "/audio/transcriptions";

    // Convert raw PCM audio to WAV format (16-bit PCM format to match Python sample.py)
    // Audio parameters: 16-bit PCM mono at 16000 Hz
    const uint32_t sample_rate = 16000;
    const uint16_t num_channels = 1;
    const uint16_t bits_per_sample = 16;
    const uint32_t byte_rate = sample_rate * num_channels * bits_per_sample / 8;
    const uint16_t block_align = num_channels * bits_per_sample / 8;
    const uint32_t data_size = audio_data.size() * sizeof(int16_t);  // PCM data size in bytes

    // For PCM format, fmt chunk is 16 bytes (no cbSize needed)
    const uint16_t fmt_chunk_size = 16;
    const uint32_t chunk_size = 4 + (8 + fmt_chunk_size) + (8 + data_size);

    // Build WAV header
    std::vector<uint8_t> wav_data;
    wav_data.reserve(44 + data_size);  // Standard WAV header is 44 bytes

    // Helper lambda to write little-endian values
    auto write_u32 = [&wav_data](uint32_t val) {
        wav_data.push_back(val & 0xFF);
        wav_data.push_back((val >> 8) & 0xFF);
        wav_data.push_back((val >> 16) & 0xFF);
        wav_data.push_back((val >> 24) & 0xFF);
    };
    auto write_u16 = [&wav_data](uint16_t val) {
        wav_data.push_back(val & 0xFF);
        wav_data.push_back((val >> 8) & 0xFF);
    };

    // RIFF header
    wav_data.push_back('R'); wav_data.push_back('I'); wav_data.push_back('F'); wav_data.push_back('F');
    write_u32(chunk_size);
    wav_data.push_back('W'); wav_data.push_back('A'); wav_data.push_back('V'); wav_data.push_back('E');

    // fmt subchunk (16 bytes for PCM)
    wav_data.push_back('f'); wav_data.push_back('m'); wav_data.push_back('t'); wav_data.push_back(' ');
    write_u32(fmt_chunk_size);           // Subchunk1Size (16 for PCM)
    write_u16(1);                         // AudioFormat (1 for PCM)
    write_u16(num_channels);
    write_u32(sample_rate);
    write_u32(byte_rate);
    write_u16(block_align);
    write_u16(bits_per_sample);

    // data subchunk
    wav_data.push_back('d'); wav_data.push_back('a'); wav_data.push_back('t'); wav_data.push_back('a');
    write_u32(data_size);

    // Append raw PCM audio data (convert int16_t samples to bytes)
    const uint8_t* pcm_bytes = reinterpret_cast<const uint8_t*>(audio_data.data());
    wav_data.insert(wav_data.end(), pcm_bytes, pcm_bytes + data_size);


    // Build multipart/form-data payload
    std::string boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";

    // Set headers
    http->SetHeader("Authorization", "Bearer " + auth_token_);
    http->SetHeader("Accept", "application/json");
    http->SetHeader("Content-Type", "multipart/form-data; boundary=" + boundary);

    // Send POST request
    if (!http->Open("POST", stt_url)) {
        ESP_LOGE(TAG, "Failed to open STT request");
        return false;
    }

    {
        // File field header
        std::string file_header;
        file_header += "--" + boundary + "\r\n";
        file_header += "Content-Disposition: form-data; name=\"file\"; filename=\"recording.wav\"\r\n";
        file_header += "Content-Type: audio/wav\r\n";
        file_header += "\r\n";
        http->Write(file_header.c_str(), file_header.size());
    }

    // WAV data
    http->Write((const char*)(wav_data.data()), wav_data.size());

    {
        // Language field
        std::string language_field;
        language_field += "\r\n--" + boundary + "\r\n";
        language_field += "Content-Disposition: form-data; name=\"language\"\r\n";
        language_field += "\r\n";
        language_field += "vi";
        http->Write(language_field.c_str(), language_field.size());
    }

    {
        // Multipart footer
        std::string multipart_footer;
        multipart_footer += "\r\n--" + boundary + "--\r\n";
        http->Write(multipart_footer.c_str(), multipart_footer.size());
    }
    http->Write("", 0);

    int status_code = http->GetStatusCode();
    if (status_code != 200) {
        std::string error_response = http->ReadAll();
        ESP_LOGE(TAG, "STT request failed with status code: %d, response: %s", status_code, error_response.c_str());
        http->Close();
        return false;
    }

    std::string response = http->ReadAll();
    std::string restr = response.c_str();
    ESP_LOGD(TAG, "STT response received: %s", response.c_str());
    http->Close();

    // Parse response
    cJSON* response_json = cJSON_Parse(response.c_str());
    ESP_LOGI(TAG, "STT text_obj: %s", response.c_str());
    if (!response_json) {
        ESP_LOGE(TAG, "Failed to parse STT response");
        return false;
    }

    cJSON* text_obj = cJSON_GetObjectItem(response_json, "text");
    if (cJSON_IsString(text_obj)) {
        transcription = text_obj->valuestring;
        ESP_LOGI(TAG, "STT transcription: %s", text_obj -> valuestring);
        cJSON_Delete(response_json);
        return true;
    }

    cJSON_Delete(response_json);
    ESP_LOGE(TAG, "Transcription text not found in STT response");
    return false;
}

bool TestProtocol::SendChatRequest(const std::string& message, std::string& response) {
    if (!authenticated_) {
        ESP_LOGE(TAG, "Not authenticated");
        return false;
    }

    ESP_LOGI(TAG, "Sending chat request: %s", message.c_str());

    auto http = CreateHttpClient();
    if (!http) {
        ESP_LOGE(TAG, "Failed to create HTTP client for chat");
        return false;
    }

    std::string chat_url = std::string(API_BASE_URL) + "/chat/completions";

    // Build JSON payload
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "model", "walle");
    cJSON_AddBoolToObject(root, "stream", false);

    cJSON* messages = cJSON_CreateArray();
    cJSON* user_message = cJSON_CreateObject();
    cJSON_AddStringToObject(user_message, "role", "user");
    cJSON_AddStringToObject(user_message, "content", message.c_str());
    cJSON_AddItemToArray(messages, user_message);
    cJSON_AddItemToObject(root, "messages", messages);

    char* json_str = cJSON_PrintUnformatted(root);
    std::string payload(json_str);
    cJSON_free(json_str);
    cJSON_Delete(root);

    // Set headers
    http->SetHeader("Authorization", "Bearer " + auth_token_);
    http->SetHeader("Content-Type", "application/json");
    http->SetContent(std::move(payload));

    // Send POST request
    if (!http->Open("POST", chat_url)) {
        ESP_LOGE(TAG, "Failed to open chat request");
        return false;
    }

    int status_code = http->GetStatusCode();
    if (status_code != 200) {
        std::string error_response = http->ReadAll();
        ESP_LOGE(TAG, "Chat request failed with status code: %d, response: %s", status_code, error_response.c_str());
        http->Close();
        return false;
    }

    std::string response_str = http->ReadAll();
    ESP_LOGD(TAG, "Chat response received: %s", response_str.c_str());
    http->Close();

    // Parse response
    cJSON* response_json = cJSON_Parse(response_str.c_str());
    if (!response_json) {
        ESP_LOGE(TAG, "Failed to parse chat response: %s", response_str.c_str());
        return false;
    }

    // Extract message content from choices[0].message.content
    cJSON* choices = cJSON_GetObjectItem(response_json, "choices");
    if (cJSON_IsArray(choices) && cJSON_GetArraySize(choices) > 0) {
        cJSON* first_choice = cJSON_GetArrayItem(choices, 0);
        cJSON* message_obj = cJSON_GetObjectItem(first_choice, "message");
        if (cJSON_IsObject(message_obj)) {
            cJSON* content = cJSON_GetObjectItem(message_obj, "content");
            if (cJSON_IsString(content)) {
                response = content->valuestring;
                ESP_LOGI(TAG, "Chat response: %s", response.c_str());
                cJSON_Delete(response_json);
                return true;
            }
        }
    }

    cJSON_Delete(response_json);
    ESP_LOGE(TAG, "Failed to extract chat response content");
    return false;
}

bool TestProtocol::SendTTSRequest(const std::string& text) {
    if (!authenticated_) {
        ESP_LOGE(TAG, "Not authenticated");
        return false;
    }

    auto http = CreateHttpClient();
    if (!http) {
        ESP_LOGE(TAG, "Failed to create HTTP client for TTS");
        return false;
    }

    std::string tts_url = std::string(API_BASE_URL) + "/audio/speech";

    // Build JSON payload
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "input", text.c_str());
    cJSON_AddStringToObject(root, "voice", TTS_VOICE_ID);

    char* json_str = cJSON_PrintUnformatted(root);
    std::string payload(json_str);
    cJSON_free(json_str);
    cJSON_Delete(root);

    // Set headers
    http->SetHeader("Authorization", "Bearer " + auth_token_);
    http->SetHeader("Content-Type", "application/json");
    http->SetHeader("Accept", "*/*");
    http->SetContent(std::move(payload));

    // Send POST request
    if (!http->Open("POST", tts_url)) {
        ESP_LOGE(TAG, "Failed to open TTS request");
        return false;
    }

    int status_code = http->GetStatusCode();
    ESP_LOGI(TAG, "Sending TTS request: %d", status_code);
    if (status_code != 200) {
        std::string error_response = http->ReadAll();
        ESP_LOGE(TAG, "TTS request failed with status code: %d, response: %s", status_code, error_response.c_str());
        http->Close();
        return false;
    }

    // Stream and decode MP3 data using chunked reading with carryover buffer
    esp_audio_err_t ret;

    // Open MP3 decoder
    void* decoder = NULL;
    ret = esp_mp3_dec_open(NULL, 0, &decoder);
    if (ret != ESP_AUDIO_ERR_OK || decoder == NULL) {
        ESP_LOGE(TAG, "Failed to open MP3 decoder");
        http->Close();
        return false;
    }

    // Buffer sizes - INPUT_BUFFER_SIZE should be large enough for multiple MP3 frames
    // MP3 frame max size is ~1441 bytes (320kbps at 44.1kHz)
    // We use a larger buffer to reduce DATA_LACK occurrences
    const size_t READ_CHUNK_SIZE = 4096;
    const size_t INPUT_BUFFER_SIZE = 8192;  // Must hold carryover + new data
    const size_t OUTPUT_BUFFER_SIZE = 8192;
    // Minimum data needed before attempting decode (at least 2 MP3 frames worth)
    const size_t MIN_DECODE_THRESHOLD = 2048;
    // PCM buffer size for batching before sending (samples, not bytes)
    // Using ~60ms worth of audio at common sample rates for memory efficiency
    const size_t PCM_BUFFER_THRESHOLD = 2880;  // ~60ms at 48kHz or ~120ms at 24kHz

    uint8_t* in_buf = (uint8_t*)malloc(INPUT_BUFFER_SIZE);
    uint8_t* out_buf = (uint8_t*)malloc(OUTPUT_BUFFER_SIZE);

    if (!in_buf || !out_buf) {
        ESP_LOGE(TAG, "Failed to allocate decoder buffers");
        free(in_buf);
        free(out_buf);
        esp_mp3_dec_close(decoder);
        http->Close();
        return false;
    }

    std::vector<int16_t> pcm_buffer;  // Buffer for accumulating PCM before sending
    int sample_rate = 0;
    int channels = 0;
    int bits_per_sample = 0;
    bool info_retrieved = false;
    size_t total_mp3_bytes = 0;
    size_t carryover_len = 0;  // Unconsumed bytes from previous iteration
    size_t total_pcm_samples = 0;
    size_t packets_sent = 0;
    bool http_eof = false;  // Track if we've reached end of HTTP stream

    // Stream MP3 data from HTTP and decode in chunks
    while (true) {
        // Calculate how much space is available in the buffer
        size_t space_available = INPUT_BUFFER_SIZE - carryover_len;
        size_t bytes_to_read = (space_available < READ_CHUNK_SIZE) ? space_available : READ_CHUNK_SIZE;

        // Read new data after any carryover bytes
        int bytes_read = 0;
        if (!http_eof && bytes_to_read > 0) {
            bytes_read = http->Read((char*)(in_buf + carryover_len), bytes_to_read);
            if (bytes_read < 0) {
                ESP_LOGE(TAG, "HTTP read error");
                break;
            }
            if (bytes_read == 0) {
                http_eof = true;
            }
            total_mp3_bytes += bytes_read;
        }

        size_t available = carryover_len + bytes_read;
        if (available == 0) {
            // No more data
            break;
        }

        // Only attempt decode if we have enough data, unless this is the final chunk
        if (available < MIN_DECODE_THRESHOLD && !http_eof) {
            carryover_len = available;
            continue;
        }

        // Process all available data in the input buffer
        uint8_t* raw_ptr = in_buf;
        uint32_t raw_len = (uint32_t)available;

        while (raw_len > 0) {
            esp_audio_dec_in_raw_t raw = {
                .buffer = raw_ptr,
                .len = raw_len,
                .consumed = 0,
                .frame_recover = ESP_AUDIO_DEC_RECOVERY_NONE,
            };

            esp_audio_dec_out_frame_t out_frame = {
                .buffer = out_buf,
                .len = OUTPUT_BUFFER_SIZE,
                .needed_size = 0,
                .decoded_size = 0,
            };

            esp_audio_dec_info_t dec_info = {};
            ret = esp_mp3_dec_decode(decoder, &raw, &out_frame, &dec_info);

            // Handle DATA_LACK: need more input data to complete a frame
            if (ret == ESP_AUDIO_ERR_DATA_LACK) {
                // If we haven't reached EOF, break to read more data
                // If EOF, we've processed all we can
                // log the current params: carryover_len, raw_len, bytes_read, total_mp3_bytes
                ESP_LOGW(TAG, "MP3 decode DATA_LACK: carryover_len=%u, raw_len=%u, bytes_read=%d, total_mp3_bytes=%u",
                         carryover_len, raw_len, bytes_read, total_mp3_bytes);
                break;
            }

            if (ret == ESP_AUDIO_ERR_OK && out_frame.decoded_size > 0) {
                // Get audio info after first successful decode
                if (!info_retrieved) {
                    sample_rate = dec_info.sample_rate;
                    channels = dec_info.channel;
                    bits_per_sample = dec_info.bits_per_sample;
                    info_retrieved = true;
                    ESP_LOGI(TAG, "MP3 format: %d Hz, %d channels, %d bits",
                             sample_rate, channels, bits_per_sample);
                }

                // Process decoded PCM data
                int16_t* samples = (int16_t*)out_frame.buffer;
                size_t num_samples = out_frame.decoded_size / sizeof(int16_t);

                // Convert stereo to mono inline if needed
                if (channels == 2) {
                    for (size_t i = 0; i < num_samples; i += 2) {
                        int32_t mixed = (static_cast<int32_t>(samples[i]) + static_cast<int32_t>(samples[i + 1])) / 2;
                        pcm_buffer.push_back(static_cast<int16_t>(mixed));
                    }
                } else {
                    pcm_buffer.insert(pcm_buffer.end(), samples, samples + num_samples);
                }

                // Send buffered PCM when threshold reached
                if (pcm_buffer.size() >= PCM_BUFFER_THRESHOLD) {
                    PlayAudioResponse(pcm_buffer, sample_rate);
                    total_pcm_samples += pcm_buffer.size();
                    packets_sent++;
                    pcm_buffer.clear();
                }
            } else if (ret != ESP_AUDIO_ERR_OK && ret != ESP_AUDIO_ERR_DATA_LACK) {
                // Log non-critical decode errors but continue processing
                ESP_LOGW(TAG, "MP3 decode warning: %d, consumed: %lu", ret, (unsigned long)raw.consumed);
            }

            // Advance input buffer by consumed amount
            if (raw.consumed > 0) {
                raw_ptr += raw.consumed;
                raw_len -= raw.consumed;
            } else {
                // No data consumed - need more input data to complete a frame
                break;
            }
        }

        // Move unconsumed data to the beginning of buffer (carryover for next iteration)
        if (raw_len > 0 && raw_ptr != in_buf) {
            memmove(in_buf, raw_ptr, raw_len);
        }
        carryover_len = raw_len;

        // If we've reached EOF and processed all data, we're done
        if (http_eof && raw_len == carryover_len && bytes_read == 0) {
            // Try one more decode attempt for any remaining data
            if (carryover_len > 0) {
                // We may have trailing data that can't form a complete frame
                ESP_LOGD(TAG, "Trailing %u bytes could not be decoded", carryover_len);
            }
            break;
        }
    }

    // Send any remaining buffered PCM data
    if (!pcm_buffer.empty()) {
        PlayAudioResponse(pcm_buffer, sample_rate);
        total_pcm_samples += pcm_buffer.size();
        packets_sent++;
    }

    ESP_LOGI(TAG, "TTS MP3 received: %u bytes, sent %u PCM samples in %u packets",
             total_mp3_bytes, total_pcm_samples, packets_sent);

    // Cleanup decoder resources
    free(in_buf);
    free(out_buf);
    esp_mp3_dec_close(decoder);
    http->Close();

    if (total_pcm_samples == 0) {
        ESP_LOGE(TAG, "No PCM data decoded from streamed MP3");
        return false;
    }

    return true;
}

bool TestProtocol::SendText(const std::string& text) {
    // This is a simple implementation - just log for now
    ESP_LOGI(TAG, "SendText called with: %s", text.c_str());
    return true;
}

bool TestProtocol::SendAudio(std::unique_ptr<AudioStreamPacket> packet) {
    if (!audio_channel_opened_) {
        ESP_LOGW(TAG, "Audio channel is not opened, ignoring audio packet");
        return false;
    }

    // Don't accumulate audio while TTS is in progress
    if (tts_in_progress_) {
        return true;
    }

    // Decode Opus packet to PCM
    std::vector<int16_t> pcm_data;
    if (!opus_decoder_->Decode(std::move(packet->payload), pcm_data)) {
        ESP_LOGE(TAG, "Failed to decode Opus packet");
        return false;
    }

    std::lock_guard<std::mutex> lock(audio_buffer_mutex_);

    // Accumulate decoded PCM audio data
    accumulated_audio_.insert(accumulated_audio_.end(),
                              pcm_data.begin(),
                              pcm_data.end());

    return true;
}

void TestProtocol::CloseAudioChannel() {
    ESP_LOGI(TAG, "Closing audio channel");
    audio_channel_opened_ = false;

    // Stop audio processing thread
    StopAudioProcessingThread();

    if (on_audio_channel_closed_ != nullptr) {
        on_audio_channel_closed_();
    }
}

bool TestProtocol::OpenAudioChannel() {
    ESP_LOGI(TAG, "Opening audio channel");

    if (!authenticated_) {
        ESP_LOGW(TAG, "Not authenticated, attempting to authenticate");
        if (!Authenticate()) {
            SetError(Lang::Strings::SERVER_NOT_CONNECTED);
            return false;
        }
    }

    // Clear accumulated audio buffer
    {
        std::lock_guard<std::mutex> lock(audio_buffer_mutex_);
        accumulated_audio_.clear();
    }

    error_occurred_ = false;
    audio_channel_opened_ = true;

    // Start audio processing thread
    StartAudioProcessingThread();

    if (on_audio_channel_opened_ != nullptr) {
        on_audio_channel_opened_();
    }

    return true;
}

bool TestProtocol::IsAudioChannelOpened() const {
    return audio_channel_opened_ && !error_occurred_ && !IsTimeout();
}

std::unique_ptr<Http> TestProtocol::CreateHttpClient() {
    auto network = Board::GetInstance().GetNetwork();
    if (!network) {
        ESP_LOGE(TAG, "Network interface is null");
        return nullptr;
    }

    auto http = network->CreateHttp();
    http->SetKeepAlive(true);
    if (!http) {
        ESP_LOGE(TAG, "Failed to create HTTP client");
        return nullptr;
    }
    return http;
}

void TestProtocol::ProcessAudioFlow() {
    ESP_LOGI(TAG, "Processing end-to-end audio flow");

    // Get accumulated audio
    std::vector<int16_t> audio_data;
    {
        std::lock_guard<std::mutex> lock(audio_buffer_mutex_);
        if (accumulated_audio_.empty()) {
            ESP_LOGW(TAG, "No audio data to process");
            return;
        }
        audio_data = std::move(accumulated_audio_);
        accumulated_audio_.clear();
    }

    ESP_LOGI(TAG, "Processing %d samples (%d bytes) of PCM audio",
             audio_data.size(), audio_data.size() * sizeof(int16_t));

    // Step 1: Send audio to STT
    std::string transcription;
    if (!SendSTTRequest(audio_data, transcription)) {
        ESP_LOGE(TAG, "STT request failed");
        SetError(Lang::Strings::SERVER_ERROR);
        return;
    }

    if (transcription.empty()) {
        ESP_LOGW(TAG, "Empty transcription received");
        return;
    }

    ESP_LOGI(TAG, "Transcription: %s", transcription.c_str());

    // Step 2: Send transcription to Chat
    std::string chat_response;
    if (!SendChatRequest(transcription, chat_response)) {
        ESP_LOGE(TAG, "Chat request failed");
        SetError(Lang::Strings::SERVER_ERROR);
        return;
    }

    if (chat_response.empty()) {
        ESP_LOGW(TAG, "Empty chat response received");
        return;
    }

    // Notify application that TTS is starting (sets device to speaking state)
    if (on_incoming_json_ != nullptr) {
        cJSON* tts_start = cJSON_CreateObject();
        cJSON_AddStringToObject(tts_start, "type", "tts");
        cJSON_AddStringToObject(tts_start, "state", "start");
        on_incoming_json_(tts_start);
        cJSON_Delete(tts_start);
    }

    // Send sentence_start with the text to display
    if (on_incoming_json_ != nullptr) {
        cJSON* sentence_start = cJSON_CreateObject();
        cJSON_AddStringToObject(sentence_start, "type", "tts");
        cJSON_AddStringToObject(sentence_start, "state", "sentence_start");
        cJSON_AddStringToObject(sentence_start, "text", chat_response.c_str());
        on_incoming_json_(sentence_start);
        cJSON_Delete(sentence_start);
    }

    // Step 3: Send chat response to TTS (audio frames are played directly during encoding)
    // Lock to prevent accumulating audio during TTS
    tts_in_progress_ = true;

    bool tts_success = SendTTSRequest(chat_response);

    tts_in_progress_ = false;

    // Notify application that TTS has stopped
    if (on_incoming_json_ != nullptr) {
        cJSON* tts_stop = cJSON_CreateObject();
        cJSON_AddStringToObject(tts_stop, "type", "tts");
        cJSON_AddStringToObject(tts_stop, "state", "stop");
        on_incoming_json_(tts_stop);
        cJSON_Delete(tts_stop);
    }

    if (!tts_success) {
        ESP_LOGE(TAG, "TTS request failed");
        SetError(Lang::Strings::SERVER_ERROR);
        return;
    }
}

void TestProtocol::PlayAudioResponse(const std::vector<int16_t>& pcm_data, int sample_rate) {
    if (on_incoming_audio_ == nullptr) {
        ESP_LOGW(TAG, "No audio callback registered, cannot play audio");
        return;
    }

    // Send PCM data directly to audio service (bypasses Opus decoding)
    auto packet = std::make_unique<AudioStreamPacket>();
    packet->sample_rate = sample_rate;
    packet->frame_duration = 0;  // Not used for PCM
    packet->timestamp = 0;
    packet->pcm_data = pcm_data;

    on_incoming_audio_(std::move(packet));
}

void TestProtocol::StartAudioProcessingThread() {
    if (audio_processing_thread_ != nullptr) {
        ESP_LOGW(TAG, "Audio processing thread already running");
        return;
    }

    audio_processing_running_ = true;

    BaseType_t result = xTaskCreate(
        AudioProcessingTask,
        "audio_proc",
        8192 * 5,  // Stack size
        this,
        5,     // Priority
        &audio_processing_thread_
    );

    if (result != pdPASS) {
        ESP_LOGE(TAG, "Failed to create audio processing thread");
        audio_processing_running_ = false;
        audio_processing_thread_ = nullptr;
    } else {
        ESP_LOGI(TAG, "Audio processing thread started");
    }
}

void TestProtocol::StopAudioProcessingThread() {
    if (audio_processing_thread_ == nullptr) {
        return;
    }

    ESP_LOGI(TAG, "Stopping audio processing thread");
    audio_processing_running_ = false;

    // Wait for thread to finish
    // Give it some time to exit gracefully
    vTaskDelay(pdMS_TO_TICKS(1000));

    if (audio_processing_thread_ != nullptr) {
        vTaskDelete(audio_processing_thread_);
        audio_processing_thread_ = nullptr;
    }

    ESP_LOGI(TAG, "Audio processing thread stopped");
}

void TestProtocol::AudioProcessingTask(void* arg) {
    TestProtocol* protocol = static_cast<TestProtocol*>(arg);

    ESP_LOGI(TAG, "Audio processing task started");

    while (protocol->audio_processing_running_) {
        // Wait for 10 seconds
        vTaskDelay(pdMS_TO_TICKS(4000));

        if (!protocol->audio_processing_running_) {
            break;
        }

        // Check if we should process audio
        if (protocol->audio_channel_opened_ && *protocol->alive_) {
            ESP_LOGI(TAG, "Processing audio flow (10 second interval)");
            protocol->ProcessAudioFlow();
        }
    }

    ESP_LOGI(TAG, "Audio processing task exiting");
    vTaskDelete(nullptr);
}
