#include "wifi_board.h"
#include "codecs/no_audio_codec.h"
#include "display/lcd_display.h"
#include "system_reset.h"
#include "application.h"
#include "button.h"
#include "config.h"
#include "power_save_timer.h"
#include "led/single_led.h"
#include "assets/lang_config.h"
#include "../xingzhi-cube-1.54tft-wifi/power_manager.h"

#include <esp_log.h>
#include <esp_lcd_panel_vendor.h>
#include <driver/spi_master.h>
#include <driver/rtc_io.h>
#include <esp_sleep.h>

#include <esp_lcd_nv3023.h>
#include "settings.h"

#define TAG "DSOLUTION_1_83_2MIC"

//   init sequence (datasheet v0.6 + standard MIPI DCS)
static const nv3023_lcd_init_cmd_t nv3030b_init_cmds[] = {
    // Unlock private registers
    {0xFD, (uint8_t[]){0x06, 0x08}, 2, 0},
    // Power & voltage
    {0x61, (uint8_t[]){0x07, 0x04}, 2, 0},
    {0x62, (uint8_t[]){0x00, 0x44, 0x40, 0x00}, 4, 0},
    {0x63, (uint8_t[]){0x41, 0x07, 0x12, 0x12}, 4, 0},
    {0x64, (uint8_t[]){0x37}, 1, 0},
    {0x65, (uint8_t[]){0x09, 0x10, 0x21}, 3, 0},
    {0x66, (uint8_t[]){0x09, 0x10, 0x21}, 3, 0},
    {0x67, (uint8_t[]){0x20, 0x40}, 2, 0},
    {0x68, (uint8_t[]){0x90, 0x4C, 0x7C, 0x06}, 4, 0},
    // Display timing
    {0xB1, (uint8_t[]){0x0F, 0x02, 0x01}, 3, 0},
    {0xB4, (uint8_t[]){0x01}, 1, 0},
    {0xB5, (uint8_t[]){0x02, 0x02, 0x0A, 0x14}, 4, 0},
    {0xB6, (uint8_t[]){0x04, 0x01, 0x9F, 0x00, 0x02}, 5, 0},
    // Gamma
    {0xDF, (uint8_t[]){0x11}, 1, 0},
    {0xE6, (uint8_t[]){0x00, 0xFF}, 2, 0},
    {0xE7, (uint8_t[]){0x01, 0x04, 0x03, 0x03, 0x00, 0x12}, 6, 0},
    {0xE8, (uint8_t[]){0x00, 0x70, 0x00}, 3, 0},
    {0xEC, (uint8_t[]){0x52}, 1, 0},
    {0xF6, (uint8_t[]){0x09, 0x10, 0x00, 0x00}, 4, 0},
    // Lock private registers
    {0xFD, (uint8_t[]){0xFA, 0xFC}, 2, 0},
    // Standard MIPI DCS
    {0x3A, (uint8_t[]){0x05}, 1, 0},   // PIXFMT: RGB565
    {0x36, (uint8_t[]){0x08}, 1, 0},   // MADCTL — tune if rotation is wrong
    {0x21, (uint8_t[]){0x00}, 0, 0},   // Inversion ON
    {0x11, (uint8_t[]){0x00}, 0, 120}, // Sleep OUT
    {0x29, (uint8_t[]){0x00}, 0, 10},  // Display ON
};

// Dsolution-specific display with UI customizations for rounded screen corners
class DsolutionSpiLcdDisplay : public SpiLcdDisplay {
public:
    DsolutionSpiLcdDisplay(esp_lcd_panel_io_handle_t panel_io, esp_lcd_panel_handle_t panel,
                           int width, int height, int offset_x, int offset_y,
                           bool mirror_x, bool mirror_y, bool swap_xy)
        : SpiLcdDisplay(panel_io, panel, width, height, offset_x, offset_y, mirror_x, mirror_y, swap_xy) {
        DisplayLockGuard lock(this);

        // Battery status: 15px from right edge to avoid cutoff by round corners
        if (top_bar_ != nullptr) {
            lv_obj_set_style_pad_right(top_bar_, 15, 0);
        }

        if (chat_message_label_ != nullptr) {
            lv_label_set_long_mode(chat_message_label_, LV_LABEL_LONG_SCROLL_CIRCULAR);
        }
    }
};

class DsolutionBoard : public WifiBoard {
private:
    Button boot_button_;
    Button volume_up_button_;
    Button volume_down_button_;
    DsolutionSpiLcdDisplay* display_;
    PowerSaveTimer* power_save_timer_;
    PowerManager* power_manager_;
    esp_lcd_panel_io_handle_t panel_io_ = nullptr;
    esp_lcd_panel_handle_t panel_ = nullptr;

    void InitializePowerManager() {
        power_manager_ = new PowerManager(POWER_CHARGE_DETECT_PIN);
        power_manager_->OnChargingStatusChanged([this](bool is_charging) {
            if (is_charging) {
                power_save_timer_->SetEnabled(false);
            } else {
                power_save_timer_->SetEnabled(true);
            }
        });
    }

    void InitializePowerSaveTimer() {
        rtc_gpio_init(POWER_SLEEP_CTRL_PIN);
        rtc_gpio_set_direction(POWER_SLEEP_CTRL_PIN, RTC_GPIO_MODE_OUTPUT_ONLY);
        rtc_gpio_set_level(POWER_SLEEP_CTRL_PIN, 1);

        power_save_timer_ = new PowerSaveTimer(-1, 60, 300);
        power_save_timer_->OnEnterSleepMode([this]() {
            GetDisplay()->SetPowerSaveMode(true);
            GetBacklight()->SetBrightness(1);
        });
        power_save_timer_->OnExitSleepMode([this]() {
            GetDisplay()->SetPowerSaveMode(false);
            GetBacklight()->RestoreBrightness();
        });
        power_save_timer_->OnShutdownRequest([this]() {
            ESP_LOGI(TAG, "Shutting down");
            rtc_gpio_set_level(POWER_SLEEP_CTRL_PIN, 0);
            rtc_gpio_hold_en(POWER_SLEEP_CTRL_PIN);
            esp_lcd_panel_disp_on_off(panel_, false);
            esp_deep_sleep_start();
        });
        power_save_timer_->SetEnabled(true);
    }

    void InitializeSpi() {
        spi_bus_config_t buscfg = {};
        buscfg.mosi_io_num = DISPLAY_SPI_MOSI_PIN;
        buscfg.miso_io_num = GPIO_NUM_NC;
        buscfg.sclk_io_num = DISPLAY_SPI_SCLK_PIN;
        buscfg.quadwp_io_num = GPIO_NUM_NC;
        buscfg.quadhd_io_num = GPIO_NUM_NC;
        buscfg.max_transfer_sz = DISPLAY_HEIGHT * 80 * sizeof(uint16_t);
        ESP_ERROR_CHECK(spi_bus_initialize(SPI3_HOST, &buscfg, SPI_DMA_CH_AUTO));
    }

    void InitializeButtons() {
        boot_button_.OnClick([this]() {
            power_save_timer_->WakeUp();
            auto& app = Application::GetInstance();
            if (app.GetDeviceState() == kDeviceStateStarting) {
                EnterWifiConfigMode();
                return;
            }
            app.ToggleChatState();
        });

        volume_up_button_.OnClick([this]() {
            power_save_timer_->WakeUp();
            auto codec = GetAudioCodec();
            auto volume = codec->output_volume() + 10;
            if (volume > 100) {
                volume = 100;
            }
            codec->SetOutputVolume(volume);
            GetDisplay()->ShowNotification(Lang::Strings::VOLUME + std::to_string(volume));
        });

        volume_up_button_.OnLongPress([this]() {
            power_save_timer_->WakeUp();
            GetAudioCodec()->SetOutputVolume(100);
            GetDisplay()->ShowNotification(Lang::Strings::MAX_VOLUME);
        });

        volume_down_button_.OnClick([this]() {
            power_save_timer_->WakeUp();
            auto codec = GetAudioCodec();
            auto volume = codec->output_volume() - 10;
            if (volume < 0) {
                volume = 0;
            }
            codec->SetOutputVolume(volume);
            GetDisplay()->ShowNotification(Lang::Strings::VOLUME + std::to_string(volume));
        });

        volume_down_button_.OnLongPress([this]() {
            power_save_timer_->WakeUp();
            GetAudioCodec()->SetOutputVolume(0);
            GetDisplay()->ShowNotification("0");
        });
    }

    void InitializeNv3030bDisplay() {
        ESP_LOGD(TAG, "Install panel IO");
        esp_lcd_panel_io_spi_config_t io_config = {};
        io_config.cs_gpio_num = DISPLAY_SPI_CS_PIN;
        io_config.dc_gpio_num = DISPLAY_SPI_DC_PIN;
        io_config.spi_mode = 0;
        io_config.pclk_hz = DISPLAY_SPI_SCLK_HZ;
        io_config.trans_queue_depth = 10;
        io_config.lcd_cmd_bits = 8;
        io_config.lcd_param_bits = 8;
        ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)SPI3_HOST, &io_config, &panel_io_));

        ESP_LOGD(TAG, "Install LCD driver");
        esp_lcd_panel_dev_config_t panel_config = {};
        nv3023_vendor_config_t vendor_config = {
            .init_cmds = nv3030b_init_cmds,
            .init_cmds_size = sizeof(nv3030b_init_cmds) / sizeof(nv3023_lcd_init_cmd_t),
        };
        panel_config.reset_gpio_num = DISPLAY_SPI_RESET_PIN;
        panel_config.rgb_ele_order = LCD_RGB_ELEMENT_ORDER_BGR;
        panel_config.bits_per_pixel = 16;
        panel_config.vendor_config = &vendor_config;

        ESP_ERROR_CHECK(esp_lcd_new_panel_nv3023(panel_io_, &panel_config, &panel_));
        ESP_ERROR_CHECK(esp_lcd_panel_reset(panel_));
        ESP_ERROR_CHECK(esp_lcd_panel_init(panel_));
        ESP_ERROR_CHECK(esp_lcd_panel_swap_xy(panel_, DISPLAY_SWAP_XY));
        ESP_ERROR_CHECK(esp_lcd_panel_mirror(panel_, DISPLAY_MIRROR_X, DISPLAY_MIRROR_Y));
        ESP_ERROR_CHECK(esp_lcd_panel_invert_color(panel_, false));
        ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(panel_, true));

        display_ = new DsolutionSpiLcdDisplay(panel_io_, panel_,
            DISPLAY_WIDTH, DISPLAY_HEIGHT, DISPLAY_OFFSET_X, DISPLAY_OFFSET_Y,
            DISPLAY_MIRROR_X, DISPLAY_MIRROR_Y, DISPLAY_SWAP_XY);
    }

public:
    DsolutionBoard() :
        boot_button_(BOOT_BUTTON_GPIO),
        volume_up_button_(VOLUME_UP_BUTTON_GPIO),
        volume_down_button_(VOLUME_DOWN_BUTTON_GPIO) {
        InitializePowerManager();
        InitializePowerSaveTimer();
        InitializeSpi();
        InitializeButtons();
        InitializeNv3030bDisplay();
        GetBacklight()->RestoreBrightness();
    }

    virtual AudioCodec* GetAudioCodec() override {
        static NoAudioCodecSimplex audio_codec(
            AUDIO_INPUT_SAMPLE_RATE,
            AUDIO_OUTPUT_SAMPLE_RATE,
            AUDIO_I2S_SPK_GPIO_BCLK,
            AUDIO_I2S_SPK_GPIO_LRCK,
            AUDIO_I2S_SPK_GPIO_DOUT,
            AUDIO_I2S_MIC_GPIO_SCK,
            AUDIO_I2S_MIC_GPIO_WS,
            AUDIO_I2S_MIC_GPIO_DIN);
        return &audio_codec;
    }

    virtual Display* GetDisplay() override {
        return display_;
    }

    virtual Backlight* GetBacklight() override {
        static PwmBacklight backlight(DISPLAY_BACKLIGHT_PIN, DISPLAY_BACKLIGHT_OUTPUT_INVERT);
        return &backlight;
    }

    virtual bool GetBatteryLevel(int& level, bool& charging, bool& discharging) override {
        static bool last_discharging = false;
        charging = power_manager_->IsCharging();
        discharging = power_manager_->IsDischarging();
        if (discharging != last_discharging) {
            power_save_timer_->SetEnabled(discharging);
            last_discharging = discharging;
        }
        level = power_manager_->GetBatteryLevel();
        return true;
    }

    virtual void SetPowerSaveLevel(PowerSaveLevel level) override {
        if (level != PowerSaveLevel::LOW_POWER) {
            power_save_timer_->WakeUp();
        }
        WifiBoard::SetPowerSaveLevel(level);
    }
};

DECLARE_BOARD(DsolutionBoard);
