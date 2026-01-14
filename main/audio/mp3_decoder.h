#ifndef MP3_DECODER_H
#define MP3_DECODER_H

#include <vector>
#include <cstdint>

class Mp3Decoder {
public:
    Mp3Decoder();
    ~Mp3Decoder();

    // Decode MP3 data to PCM samples (16-bit signed, mono or stereo depending on input)
    // Returns true on success
    // output_sample_rate and output_channels are filled with the decoded audio parameters
    bool Decode(const std::vector<uint8_t>& mp3_data,
                std::vector<int16_t>& pcm_data,
                int& output_sample_rate,
                int& output_channels);

private:
    void* decoder_; // mp3dec_t*
};

#endif // MP3_DECODER_H
