#include <map>
#include <vector>

#ifndef OPENVDAP_MESSAGE_H
#define OPENVDAP_MESSAGE_H

#  define MAX_PARTY 5
struct Environment {
};

enum COMMAND {
    LOAD_CONTRACT = 1,
    RECV_TRANSACTION,
    SEND_TRANSACTION
};


struct Message {
//  MESSAGE_TYPE type;
    const std::string conrtact_addr;
    const std::string instance_id;
};

// using DEP = std::vector<eevm::Pubkey>;
class Contract_Instance {
public:
    int state[MAX_PARTY] = {0}; // the state of an instance is an integer array of
    // transaction count
    // with the address of contract

    Contract_Instance() {
        // contract = {0};
        // instance_id = {0};
        // keys = DEP;
    };

    ~Contract_Instance() {};
};

// Initial state is the deposit record from the blockchain
struct Initial_State {
    uint32_t init_balance; // Balance on the Blockchain
    uint32_t block_height; // Current Height of blockchain while initial.
};

#endif