################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (10.3-2021.10)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Core/Src/SIGMA_iflash.c \
../Core/Src/SIGMA_main.c \
../Core/Src/SIGMA_uart.c \
../Core/Src/SIGMA_xmodem.c \
../Core/Src/hashcheck.c \
../Core/Src/stm32l5xx_hal_msp.c \
../Core/Src/stm32l5xx_it.c \
../Core/Src/syscalls.c \
../Core/Src/sysmem.c \
../Core/Src/system_stm32l5xx.c 

OBJS += \
./Core/Src/SIGMA_iflash.o \
./Core/Src/SIGMA_main.o \
./Core/Src/SIGMA_uart.o \
./Core/Src/SIGMA_xmodem.o \
./Core/Src/hashcheck.o \
./Core/Src/stm32l5xx_hal_msp.o \
./Core/Src/stm32l5xx_it.o \
./Core/Src/syscalls.o \
./Core/Src/sysmem.o \
./Core/Src/system_stm32l5xx.o 

C_DEPS += \
./Core/Src/SIGMA_iflash.d \
./Core/Src/SIGMA_main.d \
./Core/Src/SIGMA_uart.d \
./Core/Src/SIGMA_xmodem.d \
./Core/Src/hashcheck.d \
./Core/Src/stm32l5xx_hal_msp.d \
./Core/Src/stm32l5xx_it.d \
./Core/Src/syscalls.d \
./Core/Src/sysmem.d \
./Core/Src/system_stm32l5xx.d 


# Each subdirectory must supply rules for building sources it contributes
Core/Src/%.o Core/Src/%.su: ../Core/Src/%.c Core/Src/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m33 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32L552xx -c -I../Core/Inc -I../Drivers/STM32L5xx_HAL_Driver/Inc -I../Drivers/STM32L5xx_HAL_Driver/Inc/Legacy -I../Drivers/CMSIS/Device/ST/STM32L5xx/Include -I../Drivers/CMSIS/Include -I"E:/Ayoub_Data/Freelance/Sigma_Embedded/Github_Repo/Sigma_Tech_Projects/UART_Xmodem_Bootloader/Bootloader/STM32_Cryptographic" -I"E:/Ayoub_Data/Freelance/Sigma_Embedded/Github_Repo/Sigma_Tech_Projects/UART_Xmodem_Bootloader/Bootloader/STM32_Cryptographic/legacy_v3/include" -I"E:/Ayoub_Data/Freelance/Sigma_Embedded/Github_Repo/Sigma_Tech_Projects/UART_Xmodem_Bootloader/Bootloader/STM32_Cryptographic/include" -I"E:/Ayoub_Data/Freelance/Sigma_Embedded/Github_Repo/Sigma_Tech_Projects/UART_Xmodem_Bootloader/Bootloader/STM32_Cryptographic/legacy_v3/include/hash" -I"E:/Ayoub_Data/Freelance/Sigma_Embedded/Github_Repo/Sigma_Tech_Projects/UART_Xmodem_Bootloader/Bootloader/STM32_Cryptographic/include/hash" -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-Core-2f-Src

clean-Core-2f-Src:
	-$(RM) ./Core/Src/SIGMA_iflash.d ./Core/Src/SIGMA_iflash.o ./Core/Src/SIGMA_iflash.su ./Core/Src/SIGMA_main.d ./Core/Src/SIGMA_main.o ./Core/Src/SIGMA_main.su ./Core/Src/SIGMA_uart.d ./Core/Src/SIGMA_uart.o ./Core/Src/SIGMA_uart.su ./Core/Src/SIGMA_xmodem.d ./Core/Src/SIGMA_xmodem.o ./Core/Src/SIGMA_xmodem.su ./Core/Src/hashcheck.d ./Core/Src/hashcheck.o ./Core/Src/hashcheck.su ./Core/Src/stm32l5xx_hal_msp.d ./Core/Src/stm32l5xx_hal_msp.o ./Core/Src/stm32l5xx_hal_msp.su ./Core/Src/stm32l5xx_it.d ./Core/Src/stm32l5xx_it.o ./Core/Src/stm32l5xx_it.su ./Core/Src/syscalls.d ./Core/Src/syscalls.o ./Core/Src/syscalls.su ./Core/Src/sysmem.d ./Core/Src/sysmem.o ./Core/Src/sysmem.su ./Core/Src/system_stm32l5xx.d ./Core/Src/system_stm32l5xx.o ./Core/Src/system_stm32l5xx.su

.PHONY: clean-Core-2f-Src

