#include "deps/sha256.h"
#include "uint256.h"
#include "util.h"
//#include "deps/sodium.h"

// uint256 random_uint256()
// {
//     uint256 ret;
//     randombytes_buf(ret.begin(), 32);

//     return ret;
// }

class Note {
public:
    uint64_t value;
    uint256 sn;
    uint256 r;

    Note(uint64_t value, uint256 sn, uint256 r)
        : value(value), sn(sn), r(r) {}

    // Note() {
    //     //a_pk = random_uint256();
    //     sn = random_uint256();
    //     r = random_uint256();
    //     value = 0;
    // }

    uint256 cm() const{

        CSHA256 hasher;

        auto value_vec = convertIntToVectorLE(value);

        hasher.Write(&value_vec[0], value_vec.size());
        hasher.Write(sn.begin(), 32);
        hasher.Write(r.begin(), 32);

        uint256 result;
        hasher.Finalize(result.begin());

        return result;
    }
};

class NoteS {
public:
    uint64_t value;
    uint160 pk;
    uint256 sn_s;
    uint256 r;
    uint256 sn_old;

    NoteS(uint64_t value, uint160 pk, uint256 sn, uint256 r, uint256 sn_old)
        : value(value), pk(pk), sn_s(sn), r(r), sn_old(sn_old) {}

    // NoteS() {
    //     //a_pk = random_uint256();
    //     sn_s = random_uint256();
    //     r = random_uint256();
    //     value = 0;
    // }

    uint256 cm() const{

        CSHA256 hasher;

        auto value_vec = convertIntToVectorLE(value);

        hasher.Write(&value_vec[0], value_vec.size());
        hasher.Write(pk.begin(), 20);
        hasher.Write(sn_s.begin(), 32);
        hasher.Write(r.begin(), 32);
        hasher.Write(sn_old.begin(), 32);

        uint256 result;
        hasher.Finalize(result.begin());

        return result;
    }
};

class NoteHeader {
public:

    uint256 tx_root;
    uint256 state_root;
    uint256 cmtfd_root;

    NoteHeader(uint256 tx_root, uint256 state_root, uint256 cmtfd_root)
        : tx_root(tx_root), state_root(state_root), cmtfd_root(cmtfd_root) {}

    // NoteS() {
    //     //a_pk = random_uint256();
    //     sn_s = random_uint256();
    //     r = random_uint256();
    //     value = 0;
    // }

    uint256 cm() const{

        CSHA256 hasher;



        hasher.Write(tx_root.begin(), 32);
        hasher.Write(state_root.begin(), 32);
        hasher.Write(cmtfd_root.begin(), 32);

        uint256 result;
        hasher.Finalize(result.begin());

        return result;
    }
};