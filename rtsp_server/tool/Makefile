INC:=../inc
SRC:=../src
BIN:=../bin
OBJ:=../obj
MAIN:=../main

CC ?= gcc
CC_FLAG += -g -Wall -D__LINUX__
LD_FLAG:=-lrt

SOURCES_1:=$(wildcard $(SRC)/*.c)
OBJS_1:=$(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SOURCES_1))
SOURCES_2:=$(wildcard $(MAIN)/*.c)
OBJS_2:=$(patsubst $(MAIN)/%.c, $(OBJ)/%.o, $(SOURCES_2))
TARGET:=demo

all:$(BIN) $(OBJ) $(TARGET)

$(TARGET):$(OBJS_1) $(OBJS_2)
	$(CC) $(CC_FLAG) -I$(INC) -o $(BIN)/$@ $(OBJS_1) $(OBJS_2) $(LD_FLAG)

$(OBJS_1):$(OBJ)/%.o:$(SRC)/%.c
	$(CC) $(CC_FLAG) -I$(INC) -c $< -o $@ $(LD_FLAG)

$(OBJS_2):$(OBJ)/%.o:$(MAIN)/%.c
	$(CC) $(CC_FLAG) -I$(INC) -c $< -o $@ $(LD_FLAG)

$(BIN):
	@echo "Checking if $(BIN) exists..."
	@if [ ! -d "$(BIN)" ]; then \
		echo "Directory $(BIN) does not exist. Creating..."; \
		mkdir -p $(BIN); \
	else \
		echo "Directory $(BIN) already exists. Skipping creation."; \
	fi

$(OBJ):
	@echo "Checking if $(OBJ) exists..."
	@if [ ! -d "$(OBJ)" ]; then \
		echo "Directory $(OBJ) does not exist. Creating..."; \
		mkdir -p $(OBJ); \
	else \
		echo "Directory $(OBJ) already exists. Skipping creation."; \
	fi

.PRONY:clean
clean:
	@echo "Removing linked and compiled files......"
	rm -rf $(OBJ) $(BIN)
