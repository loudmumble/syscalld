package bpf

//go:generate /home/mumble/go/bin/bpf2go -type proc_data_t -type net_data_t -type fs_data_t -type mem_data_t -type mod_data_t -type syscall_data_t -type dns_data_t bpf sensors.c -- -I../headers
