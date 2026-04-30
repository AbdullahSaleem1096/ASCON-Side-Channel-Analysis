CC = gcc
CFLAGS = -Wall -Wextra -O2
ARM_CC = arm-none-eabi-gcc
ARM_CFLAGS = -mcpu=cortex-m3 -mthumb -O2 --specs=nosys.specs

SRCS = main.c ascon128.c
OBJS = $(SRCS:.c=.o)
TARGET = ascon_test
ARM_TARGET = ascon128.elf

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

arm: $(SRCS)
	$(ARM_CC) $(ARM_CFLAGS) -o $(ARM_TARGET) $^

clean:
	rm -f $(TARGET) $(ARM_TARGET) *.o

test: all
	./$(TARGET)

.PHONY: all arm clean test