#include "command.h"
#include <string>
#include <deque>
#include <iostream>
//extern oe_enclave_t *enclave;
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include "../include/command.h"
long int openvdap::Command::ms = 0;

void openvdap::Command::time_log(const char *tag) {
    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms_2 = tp.tv_sec * 1000 * 1000 + tp.tv_usec;
    std::cout << "TIME LOG: " << tag << " >>> " << ms_2 - ms << std::endl;
    ms = ms_2;
}

void openvdap::Command::time_curr(const char *tag) {
    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms_2 = tp.tv_sec * 1000 * 1000 + tp.tv_usec;
    std::cout << "LOG: " << tag << " >>> " << ms_2 << std::endl;
}

/**
 * Load the enclave from file
 * @param enc file path of enclave
 * @return
 */
int openvdap::Command::load_enclave(const char *enc) {
    oe_result_t result;
    // Create the enclave
    result = oe_create_openvdap_enclave(
            enc,
            OE_ENCLAVE_TYPE_AUTO,
            OE_ENCLAVE_FLAG_DEBUG|OE_ENCLAVE_FLAG_SIMULATE,
            NULL,
            0,
            &Global::enclave);

    if (result != OE_OK) {
        fprintf(
                stderr,
                "oe_create_openvdap_enclave(): result=%u (%s)\n",
                result,
                oe_result_str(result));
        return 0;
    }

    // Generate the TEE account
    int ret = 0;
    std::string rand = random_string(100);
    ecall_openvdap_init_tee(Global::enclave, &ret, rand.c_str(), Global::pubkey, Global::addr);
//    this->load_contract(con_path, _CONTRACT_);
    return ret;
}

/**
 * open the keynote and connect to the database
 */
void openvdap::Command::open_keynote(){
    ecall_openvdap_open_keynote(Global::enclave);
}

/**
 * close the keynote and disconnect to the database
 */
void openvdap::Command::close_keynote(){
    ecall_openvdap_close_keynote(Global::enclave);
}

void openvdap::Command::terminate_enclave() {
    if (Global::enclave)
        oe_terminate_enclave(Global::enclave);
}


void openvdap::Command::load_initial_state() {
}

void openvdap::Command::verify_initial_state(
        oe_enclave_t *enclave, const char *msg) {
}

/**
 * This is the final step to generate a group share key
 * Generate a share key to process message exchanging
 * This shared key should be attached with the instance id
 * 1. Generate an instance id
 * 2. Generate an share key
 */
void openvdap::Command::generate_share_key() {
    int ret = -1;
    // Generate an instance id
//    ecall_openvdap_generate_contract_instance_id(Global::enclave, &ret);
    // The share key should
}

/**
 * Direct send credit to the target without through contract
 */
void openvdap::Command::direct_send(std::string target, int amt) {
    unsigned char tx[16 + 64 + 32 + 32];
    unsigned char pubkey[64];
    Global::from_hex(target.c_str(), (char *) pubkey);
    time_log("Start the direct send");
//    for (int i = 0; i < 10000; i++) {
//        ecall_openvdap_direct_send(Global::enclave, (const char *) pubkey, amt, (char *) tx);
//    }
    time_log("End the direct send");
    int res =0;
//    ecall_openvdap_generate_contract_instance_id(Global::enclave,&res);
//    time_log("Start the direct send END");
//    for (int i = 0; i < 1000; i++) {
//    DEBUG("DIRECT SEND MSG");
//    this->time_curr("DIRECT SEND INTERNET");
//    }
}

/**
 * Receive direct transaction
 * @param tx direct transaction script in hex format
 */
void openvdap::Command::direct_recv(const char *tx_hex) {
    int ret = 0;
    char tx[16 + 64 + 32 + 32];
    Global::from_hex(tx_hex, (char *) tx);
    //    for (int i = 0; i < 10; ++i) {
    // time_log("Start the direct RECV");
//    ecall_openvdap_direct_recv(Global::enclave, &ret, tx);
    // time_log("Start the direct RECV END");
    if (ret == 0) {
        //            time_curr("End of the direct send process");
        std::cout << "SUCCESS" << std::endl;
    }
    //    }

    //    if (ret == 0) {
    //        time_curr("End of the direct send process");
    //        DEBUG("SUCCESS");
    //    }
}

/**
 * Send contract transaction
 * @param tx transactions in hex format
 */
void openvdap::Command::send_contract_tx(std::string target, const char *tx, int len) {
    len = (len % 16 == 0) ? len : (len + 1);
    char sign_tx[512]; // = new char[len];
    //    for (int i = 0; i < 2000; i++) {
    time_log("Start the contract  send");
//    ecall_openvdap_send(Global::enclave, tx, (char *) sign_tx);
//    time_log("Start the contract  send END");
    //    }
    int res =0;
//    ecall_openvdap_generate_contract_instance_id(Global::enclave,&res);

}

/**
 * Receive contract transaction
 * @param tx transactions in hex format
 */
void openvdap::Command::recv_contract_tx(const char *tx) {

    //    for (int i = 0; i < 2000; i++) {
    time_log("Start the contract RECV");
//    int ret = 0;
//    ecall_openvdap_recv_transaction(Global::enclave, &ret, tx);
    time_log("Start the contract  RECV END");
    //        if(ret == 0)
    //    }
}

/**
 * Get random string
 * @param length size of the random string
 * @return
 */
std::string openvdap::Command::random_string(size_t length) {
    srand(time(NULL));
    auto randchar = []() -> char {
        const char charset[] =
                "0123456789"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[rand() % max_index];
    };
    std::string str(length, 0);
    std::generate_n(str.begin(), length, randchar);
    return str;
}