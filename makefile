TEX = pdflatex
TARGET = keymaker-talk-proposal-javacard-vulnerability-scanner

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
proposal-release: clean
	$(TEX) $(FLAGS) $(SRC_DIR)/main.tex
	# biber $(BUILD_DIR)/$(basename $(TARGET)).bcf
	bibtex $(BUILD_DIR)/$(basename $(TARGET)).aux
	$(TEX) $(FLAGS) $(SRC_DIR)/main.tex
	$(TEX) $(FLAGS) $(SRC_DIR)/main.tex

build: clean proposal

.PHONY: clean build
clean-all: clean

clean:
	-rm -rf $(BUILD_DIR)
	mkdir $(BUILD_DIR)
