#define MINIMP3_IMPLEMENTATION
#include "minimp3.h"
#include "mp3_decoder.h"
#include <esp_log.h>

#define TAG "Mp3Decoder"

Mp3Decoder::Mp3Decoder() {
    decoder_ = new mp3dec_t();
    mp3dec_init(static_cast<mp3dec_t*>(decoder_));
}

Mp3Decoder::~Mp3Decoder() {
    delete static_cast<mp3dec_t*>(decoder_);
}

bool Mp3Decoder::Decode(const std::vector<uint8_t>& mp3_data,
                        std::vector<int16_t>& pcm_data,
                        int& output_sample_rate,
                        int& output_channels) {
    if (mp3_data.empty()) {
        ESP_LOGE(TAG, "Empty MP3 data");
        return false;
    }

    mp3dec_t* dec = static_cast<mp3dec_t*>(decoder_);
    mp3dec_init(dec);

    pcm_data.clear();
    output_sample_rate = 0;
    output_channels = 0;

    const uint8_t* mp3_ptr = mp3_data.data();
    int mp3_bytes_remaining = mp3_data.size();
    int16_t pcm_buffer[MINIMP3_MAX_SAMPLES_PER_FRAME];
    mp3dec_frame_info_t frame_info;

    int total_samples = 0;
    int frames_decoded = 0;

    while (mp3_bytes_remaining > 0) {
        int samples = mp3dec_decode_frame(dec, mp3_ptr, mp3_bytes_remaining, pcm_buffer, &frame_info);

        if (frame_info.frame_bytes == 0) {
            // No valid frame found, skip ahead
            if (mp3_bytes_remaining > 0) {
                mp3_ptr++;
                mp3_bytes_remaining--;
            }
            continue;
        }

        // Update position
        mp3_ptr += frame_info.frame_bytes;
        mp3_bytes_remaining -= frame_info.frame_bytes;

        if (samples > 0) {
            // First frame - store format info
            if (output_sample_rate == 0) {
                output_sample_rate = frame_info.hz;
                output_channels = frame_info.channels;
                ESP_LOGI(TAG, "MP3 format: %d Hz, %d channels, %d kbps",
                         frame_info.hz, frame_info.channels, frame_info.bitrate_kbps);
            }

            // Append decoded samples (samples is per channel, total samples = samples * channels)
            int total_frame_samples = samples * frame_info.channels;
            pcm_data.insert(pcm_data.end(), pcm_buffer, pcm_buffer + total_frame_samples);
            total_samples += total_frame_samples;
            frames_decoded++;
        }
    }

    if (frames_decoded == 0) {
        ESP_LOGE(TAG, "Failed to decode any MP3 frames");
        return false;
    }

    ESP_LOGI(TAG, "Decoded %d frames, %d total samples (%d per channel)",
             frames_decoded, total_samples, total_samples / output_channels);

    return true;
}
