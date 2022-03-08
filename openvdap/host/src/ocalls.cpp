// This is a real implementation of ocalls
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "openvdap_u.h"
#include "command.h"
#include <openenclave/host.h>
#include "Global.h"
#include <iostream>

using namespace  std;

// ocalls for printing string (C++ ocalls)
void ocall_print_error(const char *str){
    std::cout << str << std::endl;
}

void ocall_print_string(const char *str){
    std::cout << str;
}

void ocall_println_string(const char *str){
    std::cout << str << std::endl;
}

/**
 * call for a log from the enclave
 * @param tag tag of the log
 */
void ocall_openvdap_time_log()
{
    openvdap::Command::time_log("Log from the enclave");
}

/**
 * Ocall function: send transaction to target
 *
 * @param target_pubkey send target
 * @param transaction tx content
 *
 */
void ocall_openvdap_send_transaction(const char *target_pubkey, const char *transaction)
{
    //    client.
}

/**
 * Broadcast a transaction to participants of an contract instance
 * @param tx transaction in hex version or maybe in dumped json version
 * @param instance_id limit the broadcast range
 */
void ocall_openvdap_broadcast(const char *tx, const char *instance_id)
{
}

/**
 * Ocall function: Get the pubkey from the enclave
 * @param pubkey pubkey hex versoin
 * @param len size of the hex pubkey
 */
void ocall_openvdap_pubkey(const char *pubkey, size_t len)
{
}

//void test_resv_call_back(const char *tx, size_t len) {
//    // std::cout << "Call Back!" << std::endl;
//    // cout << tx << endl;
////    int ret = 0;
////    char *tx_temp = const_cast<char *>(tx);
////    tx_temp[0] = RECV_TRANSACTION;
////    ecall_openvdap_recv_transaction(enclave, &ret, tx_temp);
//}
//
//void test_send_contract_tx(oe_enclave_t *enclave) {
////    int amount = 0;
////    std::string addr = "";
////    while (true) {
////        std::cout << "Input the target address and amount of coin to send:"
////                  << std::endl;
////
////        std::cin >> addr >> amount;
////        char tx[512] = {'0'};
////
////        size_t tx_size = 512;
////
//////        eevm::Address target;
//////        _from_hex(addr.c_str(), (char *) &target);
////        time_t seconds = time(NULL);
////        cout << "Current time = " << (long long) seconds << endl;
////
////        char *addr_c = (char *) addr.c_str();
////        for (int i = 0; i < 2000; ++i) {
////            ecall_openvdap_send(enclave, (const char *) addr_c, amount, tx, tx_size);
//////             std::cout << "TX from enclave: " << tx << std::endl;
////            sck->_send(tx, tx_size);
////        }
////    }
//}


// ocalls for printing string (C++ ocalls)
void ocall_openvdap_print_error(const char* str)
{
    cerr << str << endl;
}

void ocall_openvdap_print_string(const char* str)
{
    cout << str;
}

void ocall_openvdap_println_string(const char* str)
{
    cout << str << endl;
}

int ocall_openvdap_lstat(const char *path, struct oe_stat_t* buf, size_t size){
    //printf("Entering %s\n", __func__);
    return lstat(path, (struct stat *)buf);
}

int ocall_openvdap_stat(const char *path, struct oe_stat_t* buf, size_t size){
    //printf("Entering %s\n", __func__);
    return stat(path, (struct stat *)buf);
}

int ocall_openvdap_fstat(int fd, struct oe_stat_t* buf, size_t size){
    //printf("Entering %s\n", __func__);
    return fstat(fd, (struct stat *)buf);
}

int ocall_openvdap_ftruncate(int fd, oe_off_t length){
    //printf("Entering %s\n", __func__);
    return ftruncate(fd, length);
}

char* ocall_openvdap_getcwd(char *buf, size_t size){
    //printf("Entering %s\n", __func__);
    return getcwd(buf, size);
}

int ocall_openvdap_getpid(void){
    //printf("Entering %s\n", __func__);
    return getpid();
}

int ocall_openvdap_open64(const char *filename, int flags, oe_mode_t mode){
    //printf("Entering %s\n", __func__);
    return open(filename, flags, mode); // redirect it to open() instead of open64()
}

oe_off_t ocall_openvdap_lseek64(int fd, oe_off_t offset, int whence){
    //printf("Entering %s\n", __func__);
    return lseek(fd, offset, whence); // redirect it to lseek() instead of lseek64()
}

int ocall_openvdap_read(int fd, void *buf, size_t count){
    //printf("Entering %s\n", __func__);
    return read(fd, buf, count);
}

int ocall_openvdap_write(int fd, const void *buf, size_t count){
    //printf("Entering %s\n", __func__);
    return write(fd, buf, count);
}

int ocall_openvdap_fcntl(int fd, int cmd, void* arg, size_t size){
    //printf("Entering %s\n", __func__);
    return fcntl(fd, cmd, arg);
}

int ocall_openvdap_close(int fd){
    //printf("Entering %s\n", __func__);
    return close(fd);
}

int ocall_openvdap_unlink(const char *pathname){
    //printf("Entering %s\n", __func__);
    return unlink(pathname);
}

int ocall_openvdap_getuid(void){
    //printf("Entering %s\n", __func__);
    return getuid();
}

char* ocall_openvdap_getenv(const char *name){
    //printf("Entering %s\n", __func__);
    return getenv(name);
}

int ocall_openvdap_fsync(int fd){
    //printf("Entering %s\n", __func__);
    return fsync(fd);
}