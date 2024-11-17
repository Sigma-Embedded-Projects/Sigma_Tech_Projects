################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (10.3-2021.10)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha1.c \
../STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha224.c \
../STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha256.c \
../STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha384.c \
../STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha512.c 

OBJS += \
./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha1.o \
./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha224.o \
./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha256.o \
./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha384.o \
./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha512.o 

C_DEPS += \
./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha1.d \
./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha224.d \
./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha256.d \
./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha384.d \
./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha512.d 


# Each subdirectory must supply rules for building sources it contributes
STM32_Cryptographic/legacy_v3/src/hash/%.o STM32_Cryptographic/legacy_v3/src/hash/%.su: ../STM32_Cryptographic/legacy_v3/src/hash/%.c STM32_Cryptographic/legacy_v3/src/hash/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m33 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32L552xx -c -I../Core/Inc -I../Drivers/STM32L5xx_HAL_Driver/Inc -I../Drivers/STM32L5xx_HAL_Driver/Inc/Legacy -I../Drivers/CMSIS/Device/ST/STM32L5xx/Include -I../Drivers/CMSIS/Include -I"E:/Ayoub_Data/Freelance/Sigma_Embedded/Github_Repo/Sigma_Tech_Projects/UART_Xmodem_Bootloader/Bootloader/STM32_Cryptographic" -I"E:/Ayoub_Data/Freelance/Sigma_Embedded/Github_Repo/Sigma_Tech_Projects/UART_Xmodem_Bootloader/Bootloader/STM32_Cryptographic/legacy_v3/include" -I"E:/Ayoub_Data/Freelance/Sigma_Embedded/Github_Repo/Sigma_Tech_Projects/UART_Xmodem_Bootloader/Bootloader/STM32_Cryptographic/include" -I"E:/Ayoub_Data/Freelance/Sigma_Embedded/Github_Repo/Sigma_Tech_Projects/UART_Xmodem_Bootloader/Bootloader/STM32_Cryptographic/legacy_v3/include/hash" -I"E:/Ayoub_Data/Freelance/Sigma_Embedded/Github_Repo/Sigma_Tech_Projects/UART_Xmodem_Bootloader/Bootloader/STM32_Cryptographic/include/hash" -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-STM32_Cryptographic-2f-legacy_v3-2f-src-2f-hash

clean-STM32_Cryptographic-2f-legacy_v3-2f-src-2f-hash:
	-$(RM) ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha1.d ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha1.o ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha1.su ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha224.d ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha224.o ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha224.su ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha256.d ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha256.o ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha256.su ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha384.d ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha384.o ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha384.su ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha512.d ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha512.o ./STM32_Cryptographic/legacy_v3/src/hash/legacy_v3_sha512.su

.PHONY: clean-STM32_Cryptographic-2f-legacy_v3-2f-src-2f-hash

