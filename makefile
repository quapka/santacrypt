TEX = pdflatex
TARGET = javus

BUILD_DIR = build
SRC_DIR = src

FLAGS = --shell-escape\
	--output-directory $(BUILD_DIR)\
	--jobname=$(TARGET)

# Define the targets
all: proposal

proposal:
	$(TEX) $(FLAGS) $(SRC_DIR)/main.tex

# FIXME missing bcf file
proposal-release:
	$(TEX) $(FLAGS) $(SRC_DIR)/main.tex
	biber $(BUILD_DIR)/$(basename $(TARGET)).bcf
	$(TEX) $(FLAGS) $(SRC_DIR)/main.tex
	$(TEX) $(FLAGS) $(SRC_DIR)/main.tex

build: clean proposal

.PHONY: clean build
clean-all: clean

clean:
	-rm $(BUILD_DIR)/$(TARGET).aux
	-rm $(BUILD_DIR)/$(TARGET).bbl
	-rm $(BUILD_DIR)/$(TARGET).blg
	-rm $(BUILD_DIR)/$(TARGET).log
	-rm $(BUILD_DIR)/$(TARGET).out
	-rm $(BUILD_DIR)/$(TARGET).toc
	-rm $(BUILD_DIR)/$(TARGET).lof
	-rm $(BUILD_DIR)/$(TARGET).lot
	-rm $(BUILD_DIR)/$(TARGET).pdf
