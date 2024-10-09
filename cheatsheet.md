# Cheatsheet

## Build and Run UEFI C based MtrrLib Unit Tests

Make any changes needed to C:\r\mu_basecore\UefiCpuPkg\Library\MtrrLib\UnitTest\MtrrLibUnitTest.c
C:\r\mu_basecore>stuart_ci_build -c .pytool\CISettings.py -t NOOPT TOOL_CHAIN_TAG=VS2022
C:\r\mu_basecore\Build\UefiCpuPkg\HostTest\NOOPT_VS2022\X64>MtrrLibUnitTestHost.exe > a.txt

## Capture TTT Trace and run(MtrrLib C)

tttracer MtrrLibUnitTestHost.exe
windbgx MtrrLibUnitTestHost01.run

## Capture TTT Trace and run(MtrrLib Rust)

tttracer target\debug\deps\mtrr-5607bd1f83e6856f.exe unit_test_mtrr_lib_use_case -- --nocapture
windbgx mtrr-5607bd1f83e6856f01.run

## Windbg Symbol Path

.sympath+ C:\r\mu-mtrr\target\debug\deps
.sympath+ C:\r\mu_basecore\Build\UefiCpuPkg\HostTest\NOOPT_VS2022\X64

## Windbg Src Path

.srcpath+ C:\r\mu_basecore
.srcpath+ C:\r\mu-mtrr\src

## General test execution commands

cargo test -- --test-threads=1 > b.txt
