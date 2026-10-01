# esp32-wifi-honeypot build helpers (arduino-cli in ~/tools, shares config with Arduino IDE 2.x)
#   make build SKETCH=firmware/honeypot
#   make flash SKETCH=firmware/honeypot   (or: make honeypot)
#   make monitor

CLI    ?= $(HOME)/tools/arduino-cli/arduino-cli --config-file $(HOME)/.arduinoIDE/arduino-cli.yaml
FQBN   ?= esp32:esp32:XIAO_ESP32S3:PSRAM=opi,UploadSpeed=115200
PORT   ?= /dev/ttyACM0
SKETCH ?= firmware/honeypot
# esptool's stub loader drops the USB-serial link on this setup; the ROM loader works
UPLOAD_FLAGS ?= --upload-property upload.flags=--no-stub

.PHONY: build flash monitor honeypot

build:
	$(CLI) compile --fqbn $(FQBN) $(SKETCH)

flash: build
	$(CLI) upload --fqbn $(FQBN) -p $(PORT) $(UPLOAD_FLAGS) $(SKETCH)

monitor:
	$(CLI) monitor -p $(PORT) -c baudrate=115200

# Wi-Fi honeypot sensor: flash it, then open the dashboard link it prints (or http://honeypot.local)
honeypot:
	$(MAKE) --no-print-directory flash SKETCH=firmware/honeypot
