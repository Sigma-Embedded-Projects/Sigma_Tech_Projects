################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (10.3-2021.10)
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include Drivers/STM32L5xx_HAL_Driver/Src/subdir.mk
-include Core/Startup/subdir.mk
-include Core/Src/subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(S_DEPS)),)
-include $(S_DEPS)
endif
ifneq ($(strip $(S_UPPER_DEPS)),)
-include $(S_UPPER_DEPS)
endif
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

OPTIONAL_TOOL_DEPS := \
$(wildcard ../makefile.defs) \
$(wildcard ../makefile.init) \
$(wildcard ../makefile.targets) \


BUILD_ARTIFACT_NAME := SIGMA_Embedded_APP_UART
BUILD_ARTIFACT_EXTENSION := elf
BUILD_ARTIFACT_PREFIX :=
BUILD_ARTIFACT := $(BUILD_ARTIFACT_PREFIX)$(BUILD_ARTIFACT_NAME)$(if $(BUILD_ARTIFACT_EXTENSION),.$(BUILD_ARTIFACT_EXTENSION),)

# Add inputs and outputs from these tool invocations to the build variables 
EXECUTABLES += \
SIGMA_Embedded_APP_UART.elf \

MAP_FILES += \
SIGMA_Embedded_APP_UART.map \

SIZE_OUTPUT += \
default.size.stdout \

OBJDUMP_LIST += \
SIGMA_Embedded_APP_UART.list \

OBJCOPY_HEX += \
SIGMA_Embedded_APP_UART.hex \

OBJCOPY_BIN += \
SIGMA_Embedded_APP_UART.bin \


# All Target
all:
	+@$(MAKE) --no-print-directory main-build && $(MAKE) --no-print-directory post-build

# Main-build Target
main-build: SIGMA_Embedded_APP_UART.elf secondary-outputs

# Tool invocations
SIGMA_Embedded_APP_UART.elf SIGMA_Embedded_APP_UART.map: $(OBJS) $(USER_OBJS) E:\Ayoub_Data\Freelance\Sigma_Embedded\Github_Repo\Sigma_Tech_Projects\UART_Xmodem_Bootloader\Application\STM32L552ZETXQ_FLASH.ld makefile objects.list $(OPTIONAL_TOOL_DEPS)
	arm-none-eabi-gcc -o "SIGMA_Embedded_APP_UART.elf" @"objects.list" $(USER_OBJS) $(LIBS) -mcpu=cortex-m33 -T"E:\Ayoub_Data\Freelance\Sigma_Embedded\Github_Repo\Sigma_Tech_Projects\UART_Xmodem_Bootloader\Application\STM32L552ZETXQ_FLASH.ld" --specs=nosys.specs -Wl,-Map="SIGMA_Embedded_APP_UART.map" -Wl,--gc-sections -static --specs=nano.specs -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb -Wl,--start-group -lc -lm -Wl,--end-group
	@echo 'Finished building target: $@'
	@echo ' '

default.size.stdout: $(EXECUTABLES) makefile objects.list $(OPTIONAL_TOOL_DEPS)
	arm-none-eabi-size  $(EXECUTABLES)
	@echo 'Finished building: $@'
	@echo ' '

SIGMA_Embedded_APP_UART.list: $(EXECUTABLES) makefile objects.list $(OPTIONAL_TOOL_DEPS)
	arm-none-eabi-objdump -h -S $(EXECUTABLES) > "SIGMA_Embedded_APP_UART.list"
	@echo 'Finished building: $@'
	@echo ' '

SIGMA_Embedded_APP_UART.hex: $(EXECUTABLES) makefile objects.list $(OPTIONAL_TOOL_DEPS)
	arm-none-eabi-objcopy  -O ihex $(EXECUTABLES) "SIGMA_Embedded_APP_UART.hex"
	@echo 'Finished building: $@'
	@echo ' '

SIGMA_Embedded_APP_UART.bin: $(EXECUTABLES) makefile objects.list $(OPTIONAL_TOOL_DEPS)
	arm-none-eabi-objcopy  -O binary $(EXECUTABLES) "SIGMA_Embedded_APP_UART.bin"
	@echo 'Finished building: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) SIGMA_Embedded_APP_UART.bin SIGMA_Embedded_APP_UART.elf SIGMA_Embedded_APP_UART.hex SIGMA_Embedded_APP_UART.list SIGMA_Embedded_APP_UART.map default.size.stdout
	-@echo ' '

post-build:
	bash ..\Postbuild_Scripts\Postbuild_Batch.sh
	-@echo ' '

secondary-outputs: $(SIZE_OUTPUT) $(OBJDUMP_LIST) $(OBJCOPY_HEX) $(OBJCOPY_BIN)

fail-specified-linker-script-missing:
	@echo 'Error: Cannot find the specified linker script. Check the linker settings in the build configuration.'
	@exit 2

warn-no-linker-script-specified:
	@echo 'Warning: No linker script specified. Check the linker settings in the build configuration.'

.PHONY: all clean dependents main-build fail-specified-linker-script-missing warn-no-linker-script-specified post-build

-include ../makefile.targets
