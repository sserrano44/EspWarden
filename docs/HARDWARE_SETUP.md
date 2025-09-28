# Hardware Setup Guide

This guide covers the physical setup and wiring of the ESP32 Remote Signer device.

## Required Components

### ESP32 Development Board
- **Recommended:** ESP32 NodeMCU-32S or ESP32-DevKit-C
- **Requirements:**
  - ESP32 with Secure Boot v2 support
  - At least 4MB flash memory
  - WiFi capability
  - USB programming interface

### Additional Components
- 1x Jumper wire (male-to-male)
- USB cable (USB-A to Micro-USB or USB-C depending on board)
- Optional: LED for status indication
- Optional: External antenna for better WiFi range

## GPIO Pin Configuration

### Provisioning Jumper Detection
```
GPIO 2 ──── GND (connect for provisioning mode)
```

**Important Notes:**
- GPIO 2 must be connected to GND for provisioning mode
- Pins have internal pull-up resistors enabled
- Remove connections for normal signing mode operation

### Status LED (Optional)
```
GPIO 5 ──── LED ──── 220Ω ──── GND
```

## Wiring Diagram

```
ESP32 NodeMCU-32S Board Layout:

                    [USB]
                      |
    ┌─────────────────┴─────────────────┐
    │                                   │
    │  RST  D0   D1   D2   D3   CMD  5V │
    │       │    │    │    │    │    │  │
    │       │    │    │    │    │    │  │
    │       │    │    ▼    ▼    │    │  │
    │       │    │   GPIO GPIO  │    │  │
    │       │    │    2    4    │    │  │
    │       │    │    │    │    │    │  │
    │   ┌───┴────┴────┼────┼────┴────┴──┤
    │   │ Jumper Wire ┼────┼─── GND     │
    │   │        └────┴────┘            │
    │   │                               │
    │   │  GND  D5   D6   D7   D8  3V3  │
    │   └───┴────┴────┴────┴────┴───────┘
    │        │                          │
    │        ▼                          │
    │    Status LED                     │
    │     (Optional)                    │
    └───────────────────────────────────┘
```

## Setup Steps

### 1. Initial Hardware Setup

1. **Inspect the ESP32 board**
   - Check for any physical damage
   - Ensure all pins are properly connected
   - Verify the board model supports Secure Boot

2. **Connect the USB cable**
   - Use a high-quality USB cable
   - Ensure stable connection for programming

### 2. Provisioning Mode Setup

1. **Create provisioning jumper:**
   ```
   Connect jumper wire from GPIO 2 to GND
   ```

2. **Power on the device:**
   - Connect USB cable
   - Device should start in provisioning mode
   - Look for status LED blinking pattern (if installed)

### 3. Signing Mode Setup

1. **Remove provisioning jumper:**
   - Disconnect GPIO 2 from GND
   - Store jumper safely for future use

2. **Power cycle the device:**
   - Disconnect and reconnect USB
   - Device should start in signing mode

## Status LED Patterns (Optional)

If you install a status LED on GPIO 5:

| Pattern | Meaning |
|---------|---------|
| Slow blink (1 Hz) | Provisioning mode |
| Fast blink (5 Hz) | Signing mode, not authenticated |
| Solid on | Signing mode, authenticated |
| Off | Device error or not powered |

## Power Considerations

### USB Power
- Most development scenarios use USB power
- Provides stable 5V supply
- Suitable for development and testing

### External Power
- For production deployment, consider external 5V supply
- Use quality power adapter (>=1A capacity)
- Add power filtering capacitors if needed

### Power Consumption
- Typical consumption: 160-260mA @ 3.3V
- Peak consumption during WiFi TX: ~480mA
- Sleep mode: <10mA (not used in this application)

## Enclosure Recommendations

### Development/Testing
- Use breadboard or development board as-is
- Ensure easy access to GPIO pins for jumper connections
- Keep USB port accessible

### Production Deployment
- Use protective enclosure with WiFi transparency
- Provide access panel for provisioning jumper
- Include status LED visible through enclosure
- Consider tamper-evident sealing

## Troubleshooting

### Device Not Detected
1. Check USB cable and connection
2. Verify correct driver installation
3. Try different USB port
4. Check board power LED

### Cannot Enter Provisioning Mode
1. Verify jumper connection to GND
2. Check GPIO pin number (2)
3. Ensure solid connection
4. Power cycle after connecting jumper

### WiFi Connection Issues
1. Check antenna connection (if external)
2. Verify WiFi signal strength
3. Try moving closer to router
4. Check for interference

### Flash/Programming Issues
1. Hold BOOT button while connecting USB
2. Try different baud rate
3. Check for sufficient flash memory
4. Verify ESP-IDF installation

## Safety Considerations

⚠️ **Important Safety Notes:**

1. **ESD Protection:** Handle board with anti-static precautions
2. **Power:** Never exceed 5V input voltage
3. **Connections:** Double-check all wiring before powering on
4. **Heat:** Monitor device temperature during operation
5. **Environment:** Keep device in dry, temperature-controlled environment

## Next Steps

After completing hardware setup:

1. [Install firmware](../README.md#firmware-installation)
2. [Configure device](../README.md#device-provisioning)
3. [Test with client](../client/examples/)

## Support

For hardware-related issues:
- Check the [troubleshooting section](../README.md#troubleshooting)
- Review ESP32 datasheet for pin specifications
- Consult ESP-IDF documentation for development board details