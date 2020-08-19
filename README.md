# Beaglepup

## Overview
Beaglepup is a program written in C that runs on the Beaglbone Gree Wireless board. It utilizes TCP or TLS to interact with a server.

## Setup
* Beaglebone Green Wireless 
* temperature sensor connects to Analog input 0

## Files
* `beaglepup_tcp.c`: C file for creating embedded application for TCP server
* `beaglepup_tls.c`:  C file for creating embedded application for TLS server

## Makefile targets
* `default`: builds both embedded apps
* `clean`: restores to untarred state
* `dist`: creates tarball
