# kernel-page

![Load the image!!!!!](https://i.imgur.com/0EoIKnd.jpg)

# Kernel Memory Mapping and Manipulation Project

Welcome to the Kernel Memory Mapping and Manipulation project! This project focuses on mapping two pages into kernel memory: one page acts as a buffer for reading and writing to physical memory, while the second page points to the page table entry (PTE) of the buffer page, facilitating memory operations.

## Overview

In this project, we aim to provide a mechanism for user-mode processes to interact with kernel memory safely and efficiently. We achieve this by mapping specific pages into kernel space and utilizing system calls and kernel-level hooks to facilitate memory operations.

## Features

- **Page Mapping**: Two pages are mapped into kernel memory:
  - Buffer Page: Allows reading from and writing to physical memory.
  - PTE Page: Points to the page table entry of the buffer page, enabling memory operations.

- **IAT Hooking**: NtGetStats is hooked within win32kfull.sys import table, redirecting it to a existing implementation of memmove.

- **EAT Hooking**: The export offset for "NtGetStats" within the win32kbase.sys driver has also been adjusted to enhance stealth capabilities.
