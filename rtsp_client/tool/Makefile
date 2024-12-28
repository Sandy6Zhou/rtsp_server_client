###########################################
#Makefile for simple programs
###########################################
INC:=../include
SRC:=../src
BIN:=../bin
OBJ:=../obj

CC:=gcc
CC_FLAG:=-Wall -g  -DSAVE_FILE_DEBUG -DRTSP_DEBUG
LD_FLAG:=-lpthread -lrt


SOURCES:=$(wildcard $(SRC)/*.c)
OBJS:=$(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SOURCES))
TARGET:=rtspClient
	
all:$(BIN) $(OBJ) $(TARGET)

$(TARGET):$(OBJS)
	$(CC) $(CC_FLAG) -I$(INC) -o $(BIN)/$@ $(OBJS) $(LD_FLAG)

$(OBJS):$(OBJ)/%.o:$(SRC)/%.c
	$(CC) $(CC_FLAG) -I$(INC) -c $< -o $@

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
