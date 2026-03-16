/*
 * PN532 NFC Reader/Writer for Raspberry Pi
 * Interface: I2C (recommended) or SPI
 * 
 * Dependencies:
 *   sudo apt install libnfc-dev libnfc-bin
 *   or use wiringPi for raw SPI/I2C:
 *   sudo apt install wiringpi libwiringpi-dev
 *
 * Compile:
 *   g++ pn532_nfc.cpp -o pn532_nfc -lwiringPi
 *
 * Wiring (I2C):
 *   PN532 VCC  → RPi 3.3V  (Pin 1)
 *   PN532 GND  → RPi GND   (Pin 6)
 *   PN532 SDA  → RPi GPIO2 (Pin 3)
 *   PN532 SCL  → RPi GPIO3 (Pin 5)
 *   PN532 IRQ  → RPi GPIO4 (Pin 7)  [optional but recommended]
 *
 * ⚠️  Make sure I2C is enabled:
 *   sudo raspi-config → Interface Options → I2C → Enable
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>

// ────────────────────────────────────────────────────────────────────────────
// PN532 Constants
// ────────────────────────────────────────────────────────────────────────────
#define PN532_I2C_ADDRESS       0x24
#define PN532_I2C_DEVICE        "/dev/i2c-1"

// PN532 Commands
#define PN532_CMD_GETFIRMWAREVERSION    0x02
#define PN532_CMD_SAMCONFIGURATION      0x14
#define PN532_CMD_INLISTPASSIVETARGET   0x4A
#define PN532_CMD_INDATAEXCHANGE        0x40

// MIFARE commands
#define MIFARE_CMD_AUTH_A       0x60
#define MIFARE_CMD_AUTH_B       0x61
#define MIFARE_CMD_READ         0x30
#define MIFARE_CMD_WRITE        0xA0

// Frame bytes
#define PN532_PREAMBLE          0x00
#define PN532_STARTCODE1        0x00
#define PN532_STARTCODE2        0xFF
#define PN532_POSTAMBLE         0x00
#define PN532_HOSTTOPN532       0xD4
#define PN532_PN532TOHOST       0xD5

// ────────────────────────────────────────────────────────────────────────────
// PN532 Class
// ────────────────────────────────────────────────────────────────────────────
class PN532 {
public:
    int fd;
    bool connected;

    PN532() : fd(-1), connected(false) {}

    ~PN532() {
        if (fd >= 0) close(fd);
    }

    // ── Open I2C connection ──────────────────────────────────────────────────
    bool begin() {
        fd = open(PN532_I2C_DEVICE, O_RDWR);
        if (fd < 0) {
            std::cerr << "[ERROR] Cannot open I2C device: " << PN532_I2C_DEVICE << std::endl;
            return false;
        }
        if (ioctl(fd, I2C_SLAVE, PN532_I2C_ADDRESS) < 0) {
            std::cerr << "[ERROR] Cannot set I2C address 0x" 
                      << std::hex << PN532_I2C_ADDRESS << std::endl;
            return false;
        }
        usleep(10000); // 10ms startup delay

        // Check firmware version to confirm communication
        if (!getFirmwareVersion()) {
            std::cerr << "[ERROR] PN532 not responding. Check wiring." << std::endl;
            return false;
        }

        // Configure SAM (Security Access Module)
        configureSAM();

        connected = true;
        std::cout << "[OK] PN532 connected and ready." << std::endl;
        return true;
    }

    // ── Send command frame to PN532 ──────────────────────────────────────────
    bool sendCommand(const std::vector<uint8_t>& cmd) {
        std::vector<uint8_t> frame;

        uint8_t tfi    = PN532_HOSTTOPN532;
        uint8_t len    = cmd.size() + 1; // +1 for TFI
        uint8_t lcs    = (~len) + 1;
        uint8_t dcs    = 0;

        frame.push_back(PN532_PREAMBLE);
        frame.push_back(PN532_STARTCODE1);
        frame.push_back(PN532_STARTCODE2);
        frame.push_back(len);
        frame.push_back(lcs);
        frame.push_back(tfi);

        dcs += tfi;
        for (uint8_t b : cmd) {
            frame.push_back(b);
            dcs += b;
        }

        frame.push_back((~dcs) + 1); // DCS
        frame.push_back(PN532_POSTAMBLE);

        int written = write(fd, frame.data(), frame.size());
        return written == (int)frame.size();
    }

    // ── Read response from PN532 ─────────────────────────────────────────────
    std::vector<uint8_t> readResponse(int timeout_ms = 1000) {
        usleep(50000); // 50ms wait for PN532 to process
        std::vector<uint8_t> response(64, 0);
        int bytesRead = read(fd, response.data(), response.size());
        if (bytesRead < 7) return {};

        // Find data start (after preamble + start codes + length)
        // Frame: 00 00 FF LEN LCS TFI CMD... DCS 00
        int dataStart = 6; // TFI byte is at index 5, data starts at 6
        int dataLen   = response[3] - 2; // LEN includes TFI and CMD byte

        if (dataLen <= 0 || dataStart + dataLen > bytesRead) return {};

        return std::vector<uint8_t>(
            response.begin() + dataStart,
            response.begin() + dataStart + dataLen
        );
    }

    // ── Get firmware version ─────────────────────────────────────────────────
    bool getFirmwareVersion() {
        std::vector<uint8_t> cmd = { PN532_CMD_GETFIRMWAREVERSION };
        if (!sendCommand(cmd)) return false;
        usleep(50000);
        auto resp = readResponse();
        if (resp.empty()) return false;
        std::cout << "[INFO] PN532 Firmware: IC=0x" << std::hex << (int)resp[0]
                  << " Ver=" << (int)resp[1] << "." << (int)resp[2] << std::endl;
        return true;
    }

    // ── Configure SAM ────────────────────────────────────────────────────────
    bool configureSAM() {
        // Normal mode, timeout 1s, IRQ enabled
        std::vector<uint8_t> cmd = { PN532_CMD_SAMCONFIGURATION, 0x01, 0x14, 0x01 };
        return sendCommand(cmd);
    }

    // ── Wait for and read NFC tag UID ────────────────────────────────────────
    bool readUID(std::vector<uint8_t>& uid) {
        // InListPassiveTarget: max 1 tag, ISO14443A (MIFARE)
        std::vector<uint8_t> cmd = { PN532_CMD_INLISTPASSIVETARGET, 0x01, 0x00 };
        if (!sendCommand(cmd)) return false;

        auto resp = readResponse(2000);
        if (resp.empty() || resp.size() < 6) return false;

        // Response: NbTg, Tg, ATQA(2), SAK(1), NFCIDLength, NFCID...
        uint8_t numTargets = resp[0];
        if (numTargets == 0) return false;

        uint8_t uidLen = resp[4];
        uid.assign(resp.begin() + 5, resp.begin() + 5 + uidLen);
        return true;
    }

    // ── Authenticate MIFARE block ────────────────────────────────────────────
    bool authenticate(uint8_t blockNumber, const std::vector<uint8_t>& uid,
                      const uint8_t key[6], bool useKeyA = true) {
        std::vector<uint8_t> cmd;
        cmd.push_back(PN532_CMD_INDATAEXCHANGE);
        cmd.push_back(0x01); // target number
        cmd.push_back(useKeyA ? MIFARE_CMD_AUTH_A : MIFARE_CMD_AUTH_B);
        cmd.push_back(blockNumber);
        for (int i = 0; i < 6; i++) cmd.push_back(key[i]);
        for (uint8_t b : uid) cmd.push_back(b);

        if (!sendCommand(cmd)) return false;
        auto resp = readResponse();
        return (!resp.empty() && resp[0] == 0x00);
    }

    // ── Read a MIFARE block (16 bytes) ───────────────────────────────────────
    bool readBlock(uint8_t blockNumber, std::vector<uint8_t>& data) {
        std::vector<uint8_t> cmd = {
            PN532_CMD_INDATAEXCHANGE,
            0x01,               // target
            MIFARE_CMD_READ,
            blockNumber
        };
        if (!sendCommand(cmd)) return false;
        auto resp = readResponse();
        if (resp.empty() || resp[0] != 0x00 || resp.size() < 17) return false;

        data.assign(resp.begin() + 1, resp.begin() + 17);
        return true;
    }

    // ── Write a MIFARE block (16 bytes) ──────────────────────────────────────
    bool writeBlock(uint8_t blockNumber, const std::vector<uint8_t>& data) {
        if (data.size() != 16) {
            std::cerr << "[ERROR] Block data must be exactly 16 bytes." << std::endl;
            return false;
        }
        std::vector<uint8_t> cmd = {
            PN532_CMD_INDATAEXCHANGE,
            0x01,               // target
            MIFARE_CMD_WRITE,
            blockNumber
        };
        for (uint8_t b : data) cmd.push_back(b);

        if (!sendCommand(cmd)) return false;
        auto resp = readResponse();
        return (!resp.empty() && resp[0] == 0x00);
    }

    // ── Print UID as hex string ──────────────────────────────────────────────
    static void printUID(const std::vector<uint8_t>& uid) {
        std::cout << "Tag UID: ";
        for (size_t i = 0; i < uid.size(); i++) {
            std::cout << std::uppercase << std::hex << std::setw(2)
                      << std::setfill('0') << (int)uid[i];
            if (i < uid.size() - 1) std::cout << ":";
        }
        std::cout << std::dec << std::endl;
    }

    // ── Print block data as hex ──────────────────────────────────────────────
    static void printBlock(uint8_t blockNum, const std::vector<uint8_t>& data) {
        std::cout << "Block " << std::dec << (int)blockNum << ": ";
        for (uint8_t b : data) {
            std::cout << std::uppercase << std::hex << std::setw(2)
                      << std::setfill('0') << (int)b << " ";
        }
        // Also print ASCII
        std::cout << " | ";
        for (uint8_t b : data)
            std::cout << (char)(b >= 32 && b < 127 ? b : '.');
        std::cout << std::dec << std::endl;
    }
};

// ────────────────────────────────────────────────────────────────────────────
// Helper: String to 16-byte block
// ────────────────────────────────────────────────────────────────────────────
std::vector<uint8_t> stringToBlock(const std::string& text) {
    std::vector<uint8_t> block(16, 0x00); // pad with 0x00
    size_t len = std::min(text.size(), (size_t)16);
    memcpy(block.data(), text.c_str(), len);
    return block;
}

// ────────────────────────────────────────────────────────────────────────────
// Main
// ────────────────────────────────────────────────────────────────────────────
int main() {
    PN532 nfc;

    // Default MIFARE key (factory default for most S50 cards)
    uint8_t defaultKey[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    // Block to read/write (block 4 = first block of sector 1, safe to use)
    uint8_t targetBlock = 4;

    // ── Initialize ──────────────────────────────────────────────────────────
    if (!nfc.begin()) {
        std::cerr << "[FATAL] Failed to initialize PN532." << std::endl;
        return 1;
    }

    std::cout << "\n========================================" << std::endl;
    std::cout << "  PN532 NFC Reader/Writer — Raspberry Pi" << std::endl;
    std::cout << "========================================\n" << std::endl;

    while (true) {
        std::cout << "\nCommands:" << std::endl;
        std::cout << "  [1] Read tag UID" << std::endl;
        std::cout << "  [2] Read block " << (int)targetBlock << std::endl;
        std::cout << "  [3] Write to block " << (int)targetBlock << std::endl;
        std::cout << "  [q] Quit" << std::endl;
        std::cout << "Choice: ";

        char choice;
        std::cin >> choice;

        if (choice == 'q') break;

        std::vector<uint8_t> uid;

        // ── Read UID ─────────────────────────────────────────────────────────
        if (choice == '1') {
            std::cout << "\n[*] Hold tag near reader..." << std::endl;
            if (nfc.readUID(uid)) {
                PN532::printUID(uid);
            } else {
                std::cout << "[!] No tag detected." << std::endl;
            }
        }

        // ── Read Block ───────────────────────────────────────────────────────
        else if (choice == '2') {
            std::cout << "\n[*] Hold tag near reader..." << std::endl;
            if (!nfc.readUID(uid)) {
                std::cout << "[!] No tag detected." << std::endl;
                continue;
            }
            PN532::printUID(uid);

            if (!nfc.authenticate(targetBlock, uid, defaultKey)) {
                std::cerr << "[ERROR] Authentication failed." << std::endl;
                continue;
            }

            std::vector<uint8_t> blockData;
            if (nfc.readBlock(targetBlock, blockData)) {
                PN532::printBlock(targetBlock, blockData);
            } else {
                std::cerr << "[ERROR] Failed to read block." << std::endl;
            }
        }

        // ── Write Block ──────────────────────────────────────────────────────
        else if (choice == '3') {
            std::string input;
            std::cout << "Enter text to write (max 16 chars): ";
            std::cin.ignore();
            std::getline(std::cin, input);

            std::cout << "\n[*] Hold tag near reader..." << std::endl;
            if (!nfc.readUID(uid)) {
                std::cout << "[!] No tag detected." << std::endl;
                continue;
            }
            PN532::printUID(uid);

            if (!nfc.authenticate(targetBlock, uid, defaultKey)) {
                std::cerr << "[ERROR] Authentication failed." << std::endl;
                continue;
            }

            auto blockData = stringToBlock(input);
            if (nfc.writeBlock(targetBlock, blockData)) {
                std::cout << "[OK] Written to block " << (int)targetBlock << ": " 
                          << input << std::endl;
            } else {
                std::cerr << "[ERROR] Write failed." << std::endl;
            }
        }
    }

    std::cout << "\n[INFO] Exiting." << std::endl;
    return 0;
}
