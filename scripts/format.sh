#!/bin/bash

FMT=clang-format-18

$FMT -i lib/*.c
$FMT -i examples/*.c
$FMT -i include/*.h
$FMT -i include/nvmf/*.h
