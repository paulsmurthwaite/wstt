#!/bin/bash

source ./config.sh

# Interface soft reset
./interface-down.sh
./interface-up.sh
