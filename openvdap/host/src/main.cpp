#define HOST_MAIN
#ifdef HOST_MAIN

#include "Global.h"
#include <iostream>
#include <thread>
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <string>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <boost/algorithm/string.hpp>
#include <openenclave/host.h>
#include "shared.h"
#include "command.h"

using namespace std;

static openvdap::Command *cmd;

void start_enclave(const char *enc) {

    // Start the enclave
    cmd->time_log("Start to load the enclave");
    cmd->load_enclave(enc);
    cmd->time_log("Loaded the enclave");

    cmd->time_log("Open keynote");
    // Connect to the database
    cmd->open_keynote();

}

oe_result_t command_parser(std::string line) {

    oe_result_t ret = OE_FAILURE;
    vector<string> params;
    boost::split(params, line, boost::is_any_of(" "));
    char output[1024] = {'\0'};

    if (strcmp(params[0].c_str(), "add") == 0) {
        ret = ecall_openvdap_execute_cmd_add(
                Global::enclave, params[0].c_str(), params[1].c_str(), params[2].c_str(), output);
        cout << "The value id is = " << output << endl;
    } else if (strcmp(params[0].c_str(), "update") == 0) {
        ret = ecall_openvdap_execute_cmd_update(
                Global::enclave, params[0].c_str(), params[1].c_str(), params[2].c_str());
    } else if (strcmp(params[0].c_str(), "query") == 0) {
        ret = ecall_openvdap_execute_cmd_query(
                Global::enclave, params[0].c_str(), params[2].c_str(), output);
        cout << "The value is = " << output << endl;
    } else if (strcmp(params[0].c_str(), "delete") == 0) {
        ret = ecall_openvdap_execute_cmd_delete(Global::enclave, params[0].c_str(), params[1].c_str());
        cout << "The value is = " << output << endl;
    } else if (strcmp(params[0].c_str(), "sign") == 0) {
        ret = ecall_openvdap_execute_cmd_sign(
                Global::enclave, params[0].c_str(), params[1].c_str(), output);
        cout << "The value is = " << output << endl;
    } else if (strcmp(params[0].c_str(), "verify") == 0) {
        ret = ecall_openvdap_execute_cmd_verify(
                Global::enclave, params[0].c_str(), params[1].c_str(), output);
        cout << "The value is = " << output << endl;
    } else if (strcmp(params[0].c_str(), "encryption") == 0) {
        ret = ecall_openvdap_execute_cmd_enc(
                Global::enclave, params[0].c_str(), params[1].c_str(), params[2].c_str(), output);
        cout << "The value is = " << output << endl;
    } else if (strcmp(params[0].c_str(), "decryption") == 0) {
        ret = ecall_openvdap_execute_cmd_dec(
                Global::enclave, params[0].c_str(), params[1].c_str(), output);
        cout << "The value is = " << output << endl;
    }else{
        ret = OE_OK;
    }
    return ret;
}

int main(int argc, const char *argv[]) {
    if (argc < 2) {
        std::cout << "Error : ./host [enc path]" << std::endl;
        return -1;
    }

    string line;
    oe_result_t result = OE_FAILURE;

    start_enclave(argv[1]);
    TRACE_HOST("");
    cout << "> "<<flush;
    while (getline(std::cin, line)) {
        if (line == "quit") {
            break;
        }
        if (command_parser(line) != OE_OK) {
            fprintf(
                    stderr,
                    "result=%u (%s)\n",
                    result,
                    oe_result_str(result));
            return 0;
        }
        cout << "> "<<flush;
    }
    return 0;
}

#endif