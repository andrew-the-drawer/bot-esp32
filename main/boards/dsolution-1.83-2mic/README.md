# New Board Implementation Plan: Box Dsolution 1.83 Inch 2 Mic

## Hardware Summary

| Peripheral | Chip | Interface |
|---|---|---|
| Display | NV3030B (284x240) | SPI3 |
| Boot button | — | GPIO0 |
| Volume buttons | — | GPIO39 / GPIO40 |
| Battery status | — | GPIO38 |
| Charge detect | — | GPIO47 |
| Sleep control | — | GPIO21 (RTC) |

---

## Pin Map

### Display — NV3030B
| Define | GPIO |
|---|---|
| `DISPLAY_SPI_DC_PIN` | GPIO8 |
| `DISPLAY_SPI_CS_PIN` | GPIO14 |
| `DISPLAY_SPI_SCLK_PIN` | GPIO9 |
| `DISPLAY_SPI_MOSI_PIN` | GPIO10 |
| `DISPLAY_SPI_RESET_PIN` | GPIO18 |
| `DISPLAY_BACKLIGHT_PIN` | GPIO13 |
| `DISPLAY_WIDTH` | 284 |
| `DISPLAY_HEIGHT` | 240 |
| `DISPLAY_SWAP_XY` | true |
| `DISPLAY_MIRROR_X` | false |
| `DISPLAY_MIRROR_Y` | true |
| `DISPLAY_OFFSET_X` | 0 |
| `DISPLAY_OFFSET_Y` | 0 |
| `DISPLAY_SPI_SCLK_HZ` | 80 MHz |

### Buttons & Power
| Define | GPIO |
|---|---|
| `BOOT_BUTTON_GPIO` | GPIO0 |
| `VOLUME_UP_BUTTON_GPIO` | GPIO39 |
| `VOLUME_DOWN_BUTTON_GPIO` | GPIO40 |
| `POWER_BATTERY_GPIO` | GPIO38 |
| `POWER_CHARGE_DETECT_PIN` | GPIO47 |
| `POWER_SLEEP_CTRL_PIN` | GPIO21 (RTC) |

---

## File Structure

```
main/boards/dsolution-1.83-2mic/
├── config.h          ← pin definitions
├── config.json       ← esp32s3 target + flash size
└── dsolution_1_83_2mic.cc  ← board class
```

---

## Step 1 — config.h

Standard pin-define header. No surprises; follow the same pattern as
`xingzhi-cube-0.85tft-wifi/config.h`.

Key difference: no `BUILTIN_LED_GPIO` was identified in the hardware spec.
Use `GPIO_NUM_NC` as a placeholder — confirm with hardware owner.

---

## Step 2 — config.json

```json
{
    "target": "esp32s3",
    "builds": [
        {
            "name": "dsolution-1.83-2mic",
            "sdkconfig_append": [
                "CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y",
                "CONFIG_PARTITION_TABLE_CUSTOM_FILENAME=\"partitions/v2/16m.csv\""
            ]
        }
    ]
}
```

> Flash size (16MB assumed). Confirm with hardware owner if different.

---

## Step 3 — NV3030B Display Driver Strategy

**No dedicated ESP-IDF component exists for NV3030B.**

The NV3030B uses a NewVision proprietary power-up sequence followed by standard
MIPI DCS commands (identical to ST7789 after init). The `78/esp_lcd_nv3023`
component already present in `managed_components/` accepts a custom
`nv3023_vendor_config_t` with a user-supplied `init_cmds` array — this is the
path of least resistance.

### NV3030B init sequence (from official datasheet v0.6 + TFT_eSPI PR #3315)

```c
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
    {0x36, (uint8_t[]){0x08}, 1, 0},   // MADCTL
    {0x21, (uint8_t[]){0x00}, 0, 0},   // Inversion ON
    {0x11, (uint8_t[]){0x00}, 0, 120}, // Sleep OUT
    {0x29, (uint8_t[]){0x00}, 0, 10},  // Display ON
};
```

> **Note:** The MADCTL byte (0x36) controls rotation/mirror. Tune this value
> alongside `swap_xy` / `mirror_x` / `mirror_y` during bringup if the image
> appears rotated or flipped.

---

## Step 4 — Board Class (dsolution_1_83_2mic.cc)

### Base class
`WifiBoard` (WiFi only, same as `xingzhi-cube-0.85tft-wifi`).

### Power / sleep pattern
Identical to `xingzhi-cube-0.85tft-wifi`:
- `PowerManager(POWER_CHARGE_DETECT_PIN)` for charging detection
- `PowerSaveTimer` with sleep/shutdown callbacks
- `rtc_gpio_init(POWER_SLEEP_CTRL_PIN)` held HIGH at boot, pulled LOW on shutdown
- `esp_deep_sleep_start()` for shutdown

### Methods to implement
| Method | Notes |
|---|---|
| `GetAudioCodec()` | Return `BoxAudioCodec` (static) |
| `GetDisplay()` | Return `SpiLcdDisplay*` |
| `GetBacklight()` | Return `PwmBacklight` on GPIO13 |
| `GetBatteryLevel()` | Delegate to `PowerManager` |
| `GetLed()` | `SingleLed(GPIO_NUM_NC)` — placeholder |
| `SetPowerSaveLevel()` | Wake timer + delegate to `WifiBoard` |

---

## Reference Boards

| Board | What to borrow |
|---|---|
| `xingzhi-cube-0.85tft-wifi` | Power/sleep/NV3023 display init pattern |
| `aipi-lite` | I2C init, PowerManager + PowerSaveTimer wiring |

## Links

https://dsolution.vn/so-do-phan-cung