//!
//! Stylus Hello World
//!
//! The following contract implements the Counter example from Foundry.
//!
//! ```
//! contract Counter {
//!     uint256 public number;
//!     function setNumber(uint256 newNumber) public {
//!         number = newNumber;
//!     }
//!     function increment() public {
//!         number++;
//!     }
//! }
//! ```
//!
//! The program is ABI-equivalent with Solidity, which means you can call it from both Solidity and Rust.
//! To do this, run `cargo stylus export-abi`.
//!
//! Note: this code is a template-only and has not been audited.
//!

// Allow `cargo stylus export-abi` to generate a main function.
#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

/// Use an efficient WASM allocator.
#[global_allocator]
static ALLOC: mini_alloc::MiniAlloc = mini_alloc::MiniAlloc::INIT;

use alloy_primitives::{address, Address};
use alloy_sol_types::sol_data::Address;
use hex::FromHex;
/// Import items from the SDK. The prelude contains common traits and macros.
use stylus_sdk::{
    alloy_primitives::{B256, U256},
    call::RawCall,
    crypto::keccak,
    prelude::*,
};

// use ark_bn254::{Fq, Fp};

// Define some persistent storage using the Solidity ABI.
// `Counter` will be the entrypoint.
sol_storage! {
    #[entrypoint]
    pub struct Verifier {}
}

// const q: U256 = U256::from_str_radix("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10).unwrap(); // EC group order
// const p: U256 = U256::from_str_radix("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10).unwrap(); // Prime field order

struct Point {
    x: U256,
    y: U256,
}

struct Proof {
    w1: Point,
    w2: Point,
    w3: Point,
    w4: Point,

    s: Point,
    z: Point,
    z_lookup: Point,

    t1: Point,
    t2: Point,
    t3: Point,
    t4: Point,

    W1_EVAL_LOC: U256,
    W2_EVAL_LOC: U256,
    W3_EVAL_LOC: U256,
    W4_EVAL_LOC: U256,
    S_EVAL_LOC: U256,
    Z_EVAL_LOC: U256,
    z_LOOKUP_EVAL_LOC: U256,
    Q1_EVAL_LOC: U256,
    Q2_EVAL_LOC: U256,
    Q3_EVAL_LOC: U256,
    Q4_EVAL_LOC: U256,
    QM_EVAL_LOC: U256,
    QC_EVAL_LOC: U256,
    QARITH_EVAL_LOC: U256,
    QAUX_EVAL_LOC: U256,

    SIGMA1_EVAL_LOC: U256,
    SIGMA2_EVAL_LOC: U256,
    SIGMA3_EVAL_LOC: U256,
    SIGMA4_EVAL_LOC: U256,

    TABLE1_EVAL_LOC: U256,
    TABLE2_EVAL_LOC: U256,
    TABLE3_EVAL_LOC: U256,
    TABLE4_EVAL_LOC: U256,
    TABLE_TYPE_EVAL_LOC: U256,

    ID1_EVAL_LOC: U256,
    ID2_EVAL_LOC: U256,
    ID3_EVAL_LOC: U256,
    ID4_EVAL_LOC: U256,

    W1_OMEGA_EVAL_LOC: U256,
    W2_OMEGA_EVAL_LOC: U256,
    W3_OMEGA_EVAL_LOC: U256,
    W4_OMEGA_EVAL_LOC: U256,
    S_OMEGA_EVAL_LOC: U256,
    Z_OMEGA_EVAL_LOC: U256,
    Z_LOOKUP_EVAL_LOC: U256,

    TABLE1_OMEGA_EVAL_LOC: U256,
    TABLE2_OMEGA_EVAL_LOC: U256,
    TABLE3_OMEGA_EVAL_LOC: U256,
    TABLE4_OMEGA_EVAL_LOC: U256,

    PI_Z_Y_LOC: U256,
    PI_Z_X_LOC: U256,

    PI_Z_OMEGA_Y_LOC: U256,
    PI_Z_OMEGA_X_LOC: U256,
}

impl Proof {
    fn from_bytes(proof: Vec<u8>) -> Self {
        let q = U256::from_str_radix(
            "21888242871839275222246405745257275088696311157297823662689037894645226208583",
            10,
        )
        .unwrap(); // EC group order
        let p = U256::from_str_radix(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap(); // Prime field order

        Proof {
            w1: Point {
                y: U256::from_le_slice(&proof[0x00..0x20]).reduce_mod(q),
                x: U256::from_le_slice(&proof[0x20..0x40]).reduce_mod(q),
            },

            w2: Point {
                y: U256::from_le_slice(&proof[0x40..0x60]).reduce_mod(q),
                x: U256::from_le_slice(&proof[0x60..0x80]).reduce_mod(q),
            },

            w3: Point {
                y: U256::from_le_slice(&proof[0x80..0xa0]).reduce_mod(q),
                x: U256::from_le_slice(&proof[0xa0..0xc0]).reduce_mod(q),
            },

            w4: Point {
                y: U256::from_le_slice(&proof[0xc0..0xe0]).reduce_mod(q),
                x: U256::from_le_slice(&proof[0xe0..0x100]).reduce_mod(q),
            },

            s: Point {
                y: U256::from_le_slice(&proof[0x100..0x120]).reduce_mod(q),
                x: U256::from_le_slice(&proof[0x120..0x140]).reduce_mod(q),
            },

            z: Point {
                y: U256::from_le_slice(&proof[0x140..0x160]).reduce_mod(q),
                x: U256::from_le_slice(&proof[0x160..0x180]).reduce_mod(q),
            },

            z_lookup: Point {
                y: U256::from_le_slice(&proof[0x180..0x1a0]).reduce_mod(q),
                x: U256::from_le_slice(&proof[0x1a0..0x1c0]).reduce_mod(q),
            },

            t1: Point {
                y: U256::from_le_slice(&proof[0x1c0..0x1e0]).reduce_mod(q),
                x: U256::from_le_slice(&proof[0x1e0..0x200]).reduce_mod(q),
            },

            t2: Point {
                y: U256::from_le_slice(&proof[0x200..0x220]).reduce_mod(q),
                x: U256::from_le_slice(&proof[0x220..0x240]).reduce_mod(q),
            },

            t3: Point {
                y: U256::from_le_slice(&proof[0x240..0x260]).reduce_mod(q),
                x: U256::from_le_slice(&proof[0x260..0x280]).reduce_mod(q),
            },

            t4: Point {
                y: U256::from_le_slice(&proof[0x280..0x2a0]).reduce_mod(q),
                x: U256::from_le_slice(&proof[0x2a0..0x2c0]).reduce_mod(q),
            },

            W1_EVAL_LOC: U256::from_le_slice(&proof[0x2c0..0x2e0]).reduce_mod(p),
            W2_EVAL_LOC: U256::from_le_slice(&proof[0x2e0..0x300]).reduce_mod(p),
            W3_EVAL_LOC: U256::from_le_slice(&proof[0x300..0x320]).reduce_mod(p),
            W4_EVAL_LOC: U256::from_le_slice(&proof[0x320..0x340]).reduce_mod(p),
            S_EVAL_LOC: U256::from_le_slice(&proof[0x340..0x360]).reduce_mod(p),
            Z_EVAL_LOC: U256::from_le_slice(&proof[0x360..0x380]).reduce_mod(p),
            z_LOOKUP_EVAL_LOC: U256::from_le_slice(&proof[0x380..0x3a0]).reduce_mod(p),
            Q1_EVAL_LOC: U256::from_le_slice(&proof[0x3a0..0x3c0]).reduce_mod(p),
            Q2_EVAL_LOC: U256::from_le_slice(&proof[0x3c0..0x3e0]).reduce_mod(p),
            Q3_EVAL_LOC: U256::from_le_slice(&proof[0x400..0x420]).reduce_mod(p),
            Q4_EVAL_LOC: U256::from_le_slice(&proof[0x420..0x440]).reduce_mod(p),
            QM_EVAL_LOC: U256::from_le_slice(&proof[0x440..0x460]).reduce_mod(p),
            QC_EVAL_LOC: U256::from_le_slice(&proof[0x480..0x4a0]).reduce_mod(p),
            QARITH_EVAL_LOC: U256::from_le_slice(&proof[0x4a0..0x4c0]).reduce_mod(p),
            QAUX_EVAL_LOC: U256::from_le_slice(&proof[0x4c0..0x4e0]).reduce_mod(p),

            SIGMA1_EVAL_LOC: U256::from_le_slice(&proof[0x4e0..0x500]).reduce_mod(p),
            SIGMA2_EVAL_LOC: U256::from_le_slice(&proof[0x500..0x520]).reduce_mod(p),
            SIGMA3_EVAL_LOC: U256::from_le_slice(&proof[0x520..0x540]).reduce_mod(p),
            SIGMA4_EVAL_LOC: U256::from_le_slice(&proof[0x540..0x560]).reduce_mod(p),

            TABLE1_EVAL_LOC: U256::from_le_slice(&proof[0x560..0x580]).reduce_mod(p),
            TABLE2_EVAL_LOC: U256::from_le_slice(&proof[0x580..0x5a0]).reduce_mod(p),
            TABLE3_EVAL_LOC: U256::from_le_slice(&proof[0x5a0..0x5c0]).reduce_mod(p),
            TABLE4_EVAL_LOC: U256::from_le_slice(&proof[0x5c0..0x5e0]).reduce_mod(p),
            TABLE_TYPE_EVAL_LOC: U256::from_le_slice(&proof[0x5e0..0x600]).reduce_mod(p),

            ID1_EVAL_LOC: U256::from_le_slice(&proof[0x600..0x620]).reduce_mod(p),
            ID2_EVAL_LOC: U256::from_le_slice(&proof[0x620..0x640]).reduce_mod(p),
            ID3_EVAL_LOC: U256::from_le_slice(&proof[0x640..0x660]).reduce_mod(p),
            ID4_EVAL_LOC: U256::from_le_slice(&proof[0x660..0x680]).reduce_mod(p),

            W1_OMEGA_EVAL_LOC: U256::from_le_slice(&proof[0x680..0x6a0]).reduce_mod(p),
            W2_OMEGA_EVAL_LOC: U256::from_le_slice(&proof[0x6a0..0x6c0]).reduce_mod(p),
            W3_OMEGA_EVAL_LOC: U256::from_le_slice(&proof[0x6c0..0x6e0]).reduce_mod(p),
            W4_OMEGA_EVAL_LOC: U256::from_le_slice(&proof[0x6e0..0x700]).reduce_mod(p),
            S_OMEGA_EVAL_LOC: U256::from_le_slice(&proof[0x700..0x720]).reduce_mod(p),
            Z_OMEGA_EVAL_LOC: U256::from_le_slice(&proof[0x720..0x740]).reduce_mod(p),
            Z_LOOKUP_EVAL_LOC: U256::from_le_slice(&proof[0x740..0x760]).reduce_mod(p),

            TABLE1_OMEGA_EVAL_LOC: U256::from_le_slice(&proof[0x760..0x780]).reduce_mod(p),
            TABLE2_OMEGA_EVAL_LOC: U256::from_le_slice(&proof[0x780..0x7a0]).reduce_mod(p),
            TABLE3_OMEGA_EVAL_LOC: U256::from_le_slice(&proof[0x7a0..0x7c0]).reduce_mod(p),
            TABLE4_OMEGA_EVAL_LOC: U256::from_le_slice(&proof[0x7c0..0x7e0]).reduce_mod(p),

            PI_Z_Y_LOC: U256::from_le_slice(&proof[0x7e0..0x800]).reduce_mod(q),
            PI_Z_X_LOC: U256::from_le_slice(&proof[0x800..0x820]).reduce_mod(q),

            PI_Z_OMEGA_Y_LOC: U256::from_le_slice(&proof[0x840..0x860]).reduce_mod(q),
            PI_Z_OMEGA_X_LOC: U256::from_le_slice(&proof[0x860..0x880]).reduce_mod(q),
        }
    }
}

struct VerificationKey {
    circuit_size: u32,
    num_inputs: u32,
    work_root: U256,
    work_root_inverse: U256,
    domain_inverse: U256,
    q1: Point,
    q2: Point,
    q3: Point,
    q4: Point,
    q_m: Point,
    q_c: Point,
    q_arithmetic: Point,
    q_sort: Point,
    q_elliptic: Point,
    q_aux: Point,

    sigma_1: Point,
    sigma_2: Point,
    sigma_3: Point,
    sigma_4: Point,

    table_1: Point,
    table_2: Point,
    table_3: Point,
    table_4: Point,
    table_type: Point,

    id_1: Point,
    id_2: Point,
    id_3: Point,
    id_4: Point,

    contains_recursive_proof: bool,
    recursive_proof_indices: u64,

    g2_x_X_c1: U256,
    g2_x_X_c0: U256,
    g2_x_Y_c1: U256,
    g2_x_Y_c0: U256,
}

impl Verifier {
    fn vk() -> VerificationKey {

        // Hardcoded verification key for template noir program.
        VerificationKey {
            circuit_size: 0x10,
            num_inputs: 1,
            work_root: U256::from_str_radix(
                "0x21082ca216cbbf4e1c6e4f4594dd508c996dfbe1174efb98b11509c6e306460b",
                16,
            )
            .unwrap(),
            work_root_inverse: U256::from_str_radix(
                "0x02e40daf409556c02bfc85eb303402b774954d30aeb0337eb85a71e6373428de",
                16,
            )
            .unwrap(),

            domain_inverse: U256::from_str_radix(
                "0x2d5e098bb31e86271ccb415b196942d755b0a9c3f21dd9882fa3d63ab1000001",
                16,
            )
            .unwrap(),
            q1: Point {
                x: U256::from_str_radix(
                    "0x1a8732b002f568683304140deecc1ca5ce2553c9988950ea13c198f1afe44e13",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x2c44ea8c14491b4acc57cc74ead43131d09e58937ae057f69f29b4af8ecc3441",
                    16,
                )
                .unwrap(),
            },
            q2: Point {
                x: U256::from_str_radix(
                    "0x1eebbe1207643a8bd1669b999e82265d340a5ecb1a33c0b7055734ef91200c97",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x2f08a6a07ed616c588bcf4e3555c006b27d5d1ffba12754d0718481e1a9a419a",
                    16,
                )
                .unwrap(),
            },
            q3: Point {
                x: U256::from_str_radix(
                    "0x2a7e71e447b5645910a429e7f48f1a5deba7f7d446b95a5edd242b55f67993d3",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x2b1ea7f7453a8c80a89a675245da0c33db05ba8e95ecea432ab85f6b2d6a1e86",
                    16,
                )
                .unwrap(),
            },
            q4: Point {
                x: U256::from_str_radix(
                    "0x02d6fd9e84dbe74b7531e1801405a1c292117b1a17fefe9de0bfd9edf1a84bf9",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x293c6ab3c06a0669af13393a82c60a459a3b2a0b768da45ac7af7f2aec40fc42",
                    16,
                )
                .unwrap(),
            },
            q_m: Point {
                x: U256::from_str_radix(
                    "0x0efe5ad29f99fce939416b6638dff26c845044cca9a2d9dbf94039a11d999aaa",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x0a44bf49517a4b66ae6b51eee6ac68587f768022c11ac8e37cd9dce243d01ef2",
                    16,
                )
                .unwrap(),
            },
            q_c: Point {
                x: U256::from_str_radix(
                    "0x117d457bfb28869ab380fd6e83133eeb5b6ab48e5df1ae9bc204b60817006655",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x2a958a537a99428a1019fd2c8d6b97c48f3e74ad77f0e2c63c9dfb6dccf9a29c",
                    16,
                )
                .unwrap(),
            },
            q_arithmetic: Point {
                x: U256::from_str_radix(
                    "0x18c3e78f81e83b52719158e4ac4c2f4b6c55389300451eb2a2deddf244129e7a",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x0002e9c902fe5cd49b64563cadf3bb8d7beb75f905a5894e18d27c42c62fd797",
                    16,
                )
                .unwrap(),
            },
            q_sort: Point {
                x: U256::from_str_radix(
                    "0x2cbce7beee3076b78dace04943d69d0d9e28aa6d00e046852781a5f20816645c",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x2bc27ec2e1612ea284b08bcc55b6f2fd915d11bfedbdc0e59de09e5b28952080",
                    16,
                )
                .unwrap(),
            },
            q_elliptic: Point {
                x: U256::from_str_radix(
                    "0x0ad34b5e8db72a5acf4427546c7294be6ed4f4d252a79059e505f9abc1bdf3ed",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x1e5b26790a26eb340217dd9ad28dbf90a049f42a3852acd45e6f521f24b4900e",
                    16,
                )
                .unwrap(),
            },
            q_aux: Point {
                x: U256::from_str_radix(
                    "0x155a0f51fec78c33ffceb7364d69d7ac27e570ae50bc180509764eb3fef94815",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x1c1c4720bed44a591d97cbc72b6e44b644999713a8d3c66e9054aa5726324c76",
                    16,
                )
                .unwrap(),
            },

            sigma_1: Point {
                x: U256::from_str_radix(
                    "0x210fa88bc935d90241f733cc4f011893a7d349075a0de838001178895da2aa39",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x1d270bb763cb26b2438b0760dfc7fb68fc98f87155867a2cf5c4b4ba06f637a6",
                    16,
                )
                .unwrap(),
            },
            sigma_2: Point {
                x: U256::from_str_radix(
                    "0x163a9c8b67447afccc64e9ccba9d9e826ba5b1d1ddd8d6bb960f01cd1321a169",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x19256311d43dbc795f746c63b209667653a773088aba5c6b1337f435188d72c4",
                    16,
                )
                .unwrap(),
            },
            sigma_3: Point {
                x: U256::from_str_radix(
                    "0x1aa81f5a2a21e5f2ce127892122ad0d3c35ac30e8556f343a85b66bb0207b055",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x2402d1ec00759182e950c3193c439370013802e6819544320a08b8682727f6c6",
                    16,
                )
                .unwrap(),
            },
            sigma_4: Point {
                x: U256::from_str_radix(
                    "0x2e6367e7e914347a3bb11215add814670b848a66aa5c015faedb4f2cef37454f",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x17609c6252f021456896ab4c02adc333912c2f58020c8e55fb2e52096185a0bf",
                    16,
                )
                .unwrap(),
            },

            table_1: Point {
                x: U256::from_str_radix(
                    "0x02c397073c8abce6d4140c9b961209dd783bff1a1cfc999bb29859cfb16c46fc",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x2b7bba2d1efffce0d033f596b4d030750599be670db593af86e1923fe8a1bb18",
                    16,
                )
                .unwrap(),
            },
            table_2: Point {
                x: U256::from_str_radix(
                    "0x2c71c58b66498f903b3bbbda3d05ce8ffb571a4b3cf83533f3f71b99a04f6e6b",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x039dce37f94d1bbd97ccea32a224fe2afaefbcbd080c84dcea90b54f4e0a858f",
                    16,
                )
                .unwrap(),
            },
            table_3: Point {
                x: U256::from_str_radix(
                    "0x27dc44977efe6b3746a290706f4f7275783c73cfe56847d848fd93b63bf32083",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x0a5366266dd7b71a10b356030226a2de0cbf2edc8f085b16d73652b15eced8f5",
                    16,
                )
                .unwrap(),
            },
            table_4: Point {
                x: U256::from_str_radix(
                    "0x136097d79e1b0ae373255e8760c49900a7588ec4d6809c90bb451005a3de3077",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x13dd7515ccac4095302d204f06f0bff2595d77bdf72e4acdb0b0b43969860d98",
                    16,
                )
                .unwrap(),
            },
            table_type: Point {
                x: U256::from_str_radix(
                    "0x16ff3501369121d410b445929239ba057fe211dad1b706e49a3b55920fac20ec",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x1e190987ebd9cf480f608b82134a00eb8007673c1ed10b834a695adf0068522a",
                    16,
                )
                .unwrap(),
            },

            id_1: Point {
                x: U256::from_str_radix(
                    "0x068ae63477ca649fffc34e466c212c208b89ff7dfebff7831183169ea0cfd64d",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x0d44dc459b23e94ce13c419e7feeb1d4bb61991ce667557d0ecc1ee6c29b3c3b",
                    16,
                )
                .unwrap(),
            },
            id_2: Point {
                x: U256::from_str_radix(
                    "0x093cf3ec6e1328ec2e9963bae3f0769bd8eb45e32cb91e2435d33daf3b336ea9",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x29432aa4a2a667ca8a6781517f689f573e78164764701f7190e07eeb282d7752",
                    16,
                )
                .unwrap(),
            },
            id_3: Point {
                x: U256::from_str_radix(
                    "0x211045f9f4618ac7e73d1ba72682487e558f73d6737ff3645a9824352fb90e51",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x012d9c85c11bcc8b2407f4764c4209c06e9027d21764554f5a20e9361d4d94ba",
                    16,
                )
                .unwrap(),
            },
            id_4: Point {
                x: U256::from_str_radix(
                    "0x2eea648c8732596b1314fe2a4d2f05363f0c994e91cecad25835338edee2294f",
                    16,
                )
                .unwrap(),
                y: U256::from_str_radix(
                    "0x0ab49886c2b94bd0bd3f6ed1dbbe2cb2671d2ae51d31c1210433c3972bb64578",
                    16,
                )
                .unwrap(),
            },

            contains_recursive_proof: false,
            recursive_proof_indices: 0,

            g2_x_X_c1: U256::from_str_radix(
                "0x260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1",
                16,
            )
            .unwrap(),
            g2_x_X_c0: U256::from_str_radix(
                "0x0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0",
                16,
            )
            .unwrap(),
            g2_x_Y_c1: U256::from_str_radix(
                "0x04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4",
                16,
            )
            .unwrap(),
            g2_x_Y_c0: U256::from_str_radix(
                "0x22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55",
                16,
            )
            .unwrap(),
        }

        // mstore(add(_vk, 0x00), 0x0000000000000000000000000000000000000000000000000000000000000010) // vk.circuit_size
        // mstore(add(_vk, 0x20), 0x0000000000000000000000000000000000000000000000000000000000000001) // vk.num_inputs
        // mstore(add(_vk, 0x40), 0x21082ca216cbbf4e1c6e4f4594dd508c996dfbe1174efb98b11509c6e306460b) // vk.work_root
        // mstore(add(_vk, 0x60), 0x2d5e098bb31e86271ccb415b196942d755b0a9c3f21dd9882fa3d63ab1000001) // vk.domain_inverse
        // mstore(add(_vk, 0x80), 0x1a8732b002f568683304140deecc1ca5ce2553c9988950ea13c198f1afe44e13) // vk.Q1.x
        // mstore(add(_vk, 0xa0), 0x2c44ea8c14491b4acc57cc74ead43131d09e58937ae057f69f29b4af8ecc3441) // vk.Q1.y
        // mstore(add(_vk, 0xc0), 0x1eebbe1207643a8bd1669b999e82265d340a5ecb1a33c0b7055734ef91200c97) // vk.Q2.x
        // mstore(add(_vk, 0xe0), 0x2f08a6a07ed616c588bcf4e3555c006b27d5d1ffba12754d0718481e1a9a419a) // vk.Q2.y
        // mstore(add(_vk, 0x100), 0x2a7e71e447b5645910a429e7f48f1a5deba7f7d446b95a5edd242b55f67993d3) // vk.Q3.x
        // mstore(add(_vk, 0x120), 0x2b1ea7f7453a8c80a89a675245da0c33db05ba8e95ecea432ab85f6b2d6a1e86) // vk.Q3.y
        // mstore(add(_vk, 0x140), 0x02d6fd9e84dbe74b7531e1801405a1c292117b1a17fefe9de0bfd9edf1a84bf9) // vk.Q4.x
        // mstore(add(_vk, 0x160), 0x293c6ab3c06a0669af13393a82c60a459a3b2a0b768da45ac7af7f2aec40fc42) // vk.Q4.y
        // mstore(add(_vk, 0x180), 0x0efe5ad29f99fce939416b6638dff26c845044cca9a2d9dbf94039a11d999aaa) // vk.Q_M.x
        // mstore(add(_vk, 0x1a0), 0x0a44bf49517a4b66ae6b51eee6ac68587f768022c11ac8e37cd9dce243d01ef2) // vk.Q_M.y
        // mstore(add(_vk, 0x1c0), 0x117d457bfb28869ab380fd6e83133eeb5b6ab48e5df1ae9bc204b60817006655) // vk.Q_C.x
        // mstore(add(_vk, 0x1e0), 0x2a958a537a99428a1019fd2c8d6b97c48f3e74ad77f0e2c63c9dfb6dccf9a29c) // vk.Q_C.y
        // mstore(add(_vk, 0x200), 0x18c3e78f81e83b52719158e4ac4c2f4b6c55389300451eb2a2deddf244129e7a) // vk.Q_ARITHMETIC.x
        // mstore(add(_vk, 0x220), 0x0002e9c902fe5cd49b64563cadf3bb8d7beb75f905a5894e18d27c42c62fd797) // vk.Q_ARITHMETIC.y
        // mstore(add(_vk, 0x240), 0x2cbce7beee3076b78dace04943d69d0d9e28aa6d00e046852781a5f20816645c) // vk.QSORT.x
        // mstore(add(_vk, 0x260), 0x2bc27ec2e1612ea284b08bcc55b6f2fd915d11bfedbdc0e59de09e5b28952080) // vk.QSORT.y
        // mstore(add(_vk, 0x280), 0x0ad34b5e8db72a5acf4427546c7294be6ed4f4d252a79059e505f9abc1bdf3ed) // vk.Q_ELLIPTIC.x
        // mstore(add(_vk, 0x2a0), 0x1e5b26790a26eb340217dd9ad28dbf90a049f42a3852acd45e6f521f24b4900e) // vk.Q_ELLIPTIC.y
        // mstore(add(_vk, 0x2c0), 0x155a0f51fec78c33ffceb7364d69d7ac27e570ae50bc180509764eb3fef94815) // vk.Q_AUX.x
        // mstore(add(_vk, 0x2e0), 0x1c1c4720bed44a591d97cbc72b6e44b644999713a8d3c66e9054aa5726324c76) // vk.Q_AUX.y
        // mstore(add(_vk, 0x300), 0x210fa88bc935d90241f733cc4f011893a7d349075a0de838001178895da2aa39) // vk.SIGMA1.x
        // mstore(add(_vk, 0x320), 0x1d270bb763cb26b2438b0760dfc7fb68fc98f87155867a2cf5c4b4ba06f637a6) // vk.SIGMA1.y
        // mstore(add(_vk, 0x340), 0x163a9c8b67447afccc64e9ccba9d9e826ba5b1d1ddd8d6bb960f01cd1321a169) // vk.SIGMA2.x
        // mstore(add(_vk, 0x360), 0x19256311d43dbc795f746c63b209667653a773088aba5c6b1337f435188d72c4) // vk.SIGMA2.y
        // mstore(add(_vk, 0x380), 0x1aa81f5a2a21e5f2ce127892122ad0d3c35ac30e8556f343a85b66bb0207b055) // vk.SIGMA3.x
        // mstore(add(_vk, 0x3a0), 0x2402d1ec00759182e950c3193c439370013802e6819544320a08b8682727f6c6) // vk.SIGMA3.y
        // mstore(add(_vk, 0x3c0), 0x2e6367e7e914347a3bb11215add814670b848a66aa5c015faedb4f2cef37454f) // vk.SIGMA4.x
        // mstore(add(_vk, 0x3e0), 0x17609c6252f021456896ab4c02adc333912c2f58020c8e55fb2e52096185a0bf) // vk.SIGMA4.y
        // mstore(add(_vk, 0x400), 0x02c397073c8abce6d4140c9b961209dd783bff1a1cfc999bb29859cfb16c46fc) // vk.TABLE1.x
        // mstore(add(_vk, 0x420), 0x2b7bba2d1efffce0d033f596b4d030750599be670db593af86e1923fe8a1bb18) // vk.TABLE1.y
        // mstore(add(_vk, 0x440), 0x2c71c58b66498f903b3bbbda3d05ce8ffb571a4b3cf83533f3f71b99a04f6e6b) // vk.TABLE2.x
        // mstore(add(_vk, 0x460), 0x039dce37f94d1bbd97ccea32a224fe2afaefbcbd080c84dcea90b54f4e0a858f) // vk.TABLE2.y
        // mstore(add(_vk, 0x480), 0x27dc44977efe6b3746a290706f4f7275783c73cfe56847d848fd93b63bf32083) // vk.TABLE3.x
        // mstore(add(_vk, 0x4a0), 0x0a5366266dd7b71a10b356030226a2de0cbf2edc8f085b16d73652b15eced8f5) // vk.TABLE3.y
        // mstore(add(_vk, 0x4c0), 0x136097d79e1b0ae373255e8760c49900a7588ec4d6809c90bb451005a3de3077) // vk.TABLE4.x
        // mstore(add(_vk, 0x4e0), 0x13dd7515ccac4095302d204f06f0bff2595d77bdf72e4acdb0b0b43969860d98) // vk.TABLE4.y
        // mstore(add(_vk, 0x500), 0x16ff3501369121d410b445929239ba057fe211dad1b706e49a3b55920fac20ec) // vk.TABLE_TYPE.x
        // mstore(add(_vk, 0x520), 0x1e190987ebd9cf480f608b82134a00eb8007673c1ed10b834a695adf0068522a) // vk.TABLE_TYPE.y
        // mstore(add(_vk, 0x540), 0x068ae63477ca649fffc34e466c212c208b89ff7dfebff7831183169ea0cfd64d) // vk.ID1.x
        // mstore(add(_vk, 0x560), 0x0d44dc459b23e94ce13c419e7feeb1d4bb61991ce667557d0ecc1ee6c29b3c3b) // vk.ID1.y
        // mstore(add(_vk, 0x580), 0x093cf3ec6e1328ec2e9963bae3f0769bd8eb45e32cb91e2435d33daf3b336ea9) // vk.ID2.x
        // mstore(add(_vk, 0x5a0), 0x29432aa4a2a667ca8a6781517f689f573e78164764701f7190e07eeb282d7752) // vk.ID2.y
        // mstore(add(_vk, 0x5c0), 0x211045f9f4618ac7e73d1ba72682487e558f73d6737ff3645a9824352fb90e51) // vk.ID3.x
        // mstore(add(_vk, 0x5e0), 0x012d9c85c11bcc8b2407f4764c4209c06e9027d21764554f5a20e9361d4d94ba) // vk.ID3.y
        // mstore(add(_vk, 0x600), 0x2eea648c8732596b1314fe2a4d2f05363f0c994e91cecad25835338edee2294f) // vk.ID4.x
        // mstore(add(_vk, 0x620), 0x0ab49886c2b94bd0bd3f6ed1dbbe2cb2671d2ae51d31c1210433c3972bb64578) // vk.ID4.y
        // mstore(add(_vk, 0x640), 0x00) // vk.contains_recursive_proof
        // mstore(add(_vk, 0x660), 0) // vk.recursive_proof_public_input_indices
        // mstore(add(_vk, 0x680), 0x260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1) // vk.g2_x.X.c1
        // mstore(add(_vk, 0x6a0), 0x0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0) // vk.g2_x.X.c0
        // mstore(add(_vk, 0x6c0), 0x04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4) // vk.g2_x.Y.c1
        // mstore(add(_vk, 0x6e0), 0x22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55) // vk.g2_x.Y.c0
        // mstore(_omegaInverseLoc, 0x02e40daf409556c02bfc85eb303402b774954d30aeb0337eb85a71e6373428de) // vk.work_root_inverse
    }

    fn is_on_curve(point: Point) -> bool {
        let q = U256::from_str_radix(
            "21888242871839275222246405745257275088696311157297823662689037894645226208583",
            10,
        )
        .unwrap(); // EC group order

        let xx = point.x.mul_mod(point.x, q);
        let xxx = xx.mul_mod(point.x, q);
        let yy = point.y.mul_mod(point.y, q);

        // y^2 == x^3 + 3
        yy == xxx.add_mod(U256::from(3), q)
    }

    // COMPUTE PUBLIC INPUT DELTA
    // ΔPI = ∏ᵢ∈ℓ(wᵢ + β σ(i) + γ) / ∏ᵢ∈ℓ(wᵢ + β σ'(i) + γ)
    fn get_public_input_delta(
        beta: U256,
        gamma: U256,
        work_root: U256,
        public_inputs: Vec<U256>,
    ) -> Result<(U256, U256), ()> {
        let p = U256::from_str_radix(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap(); // Prime field order

        let mut numerator_value: U256 = U256::from(1);
        let mut denominator_value: U256 = U256::from(1);

        // root_1 = β * 0x05
        let mut root_1 = beta.mul_mod(U256::wrapping_from(0x05), p);
        // root_2 = β * 0x0c
        let mut root_2 = beta.mul_mod(U256::wrapping_from(0x0c), p);
        for public_input in public_inputs {
            if public_input.lt(&p) {
                return Err(());
            };
            let temp = public_input.add_mod(gamma, p);

            numerator_value = numerator_value.mul_mod(root_1 + temp, p);
            denominator_value = denominator_value.mul_mod(root_2 + temp, p);

            root_1 = root_1.mul_mod(work_root, p);
            root_2 = root_2.mul_mod(work_root, p);
        }

        Ok((root_1, root_2))
    }

    // Compute Plookup delta factor [γ(1 + β)]^{n-k}
    // k = num roots cut out of Z_H = 4
    fn get_plookup_delta_factor(
        beta: U256,
        gamma: U256,
        circuit_size: u32,
    ) -> Result<(U256, U256), ()> {
        let p = U256::from_str_radix(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap(); // Prime field order

        let delta_base = gamma.mul_mod(beta.add_mod(U256::wrapping_from(1), p), p);
        let mut delta_numerator = delta_base;
        let mut count = 1;

        while count < circuit_size {
            delta_numerator = delta_numerator.mul_mod(delta_numerator, p);
            count *= 2;
        }

        let delta_denominator = delta_base.mul_mod(delta_base, p);
        let delta_denominator = delta_denominator.mul_mod(delta_denominator, p);

        Ok((delta_numerator, delta_denominator))
    }

    /// Compute lagrange poly and vanishing poly fractions
    fn get_lagrange_poly_and_vanishing_poly_fractions(
        zeta: U256,
        delta_numerator_root: U256,
        delta_denominator_root: U256,
        plookup_delta_numerator_root: U256,
        plookup_delta_denominator_root: U256,
        vk: &VerificationKey,
    ) -> Result<(U256, U256, U256, U256, U256, U256, U256), ()> {
        let p = U256::from_str_radix(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap(); // Prime field order
        let p_sub_1 = p.saturating_sub(U256::wrapping_from(1));
        let p_sub_2 = p.saturating_sub(U256::wrapping_from(2));

        let mut vanishing_numerator = zeta;
        let mut count = 1;
        while count < vk.circuit_size {
            vanishing_numerator = vanishing_numerator.mul_mod(vanishing_numerator, p);
            count *= 2;
        }

        let ZETA_POW_N_LOC = vanishing_numerator;
        vanishing_numerator = vanishing_numerator.add_mod(p_sub_1, p);

        let mut accumulating_root = vk.work_root_inverse;
        let mut work_root = p.saturating_sub(accumulating_root);
        let domain_inverse = vk.domain_inverse;

        let mut vanishing_denominator = zeta.add_mod(work_root, p);
        work_root = work_root.mul_mod(accumulating_root, p);
        vanishing_denominator = vanishing_denominator.add_mod(zeta.add_mod(work_root, p), p);
        work_root = work_root.mul_mod(accumulating_root, p);
        vanishing_denominator = vanishing_denominator.mul_mod(zeta.add_mod(work_root, p), p);
        vanishing_denominator = vanishing_denominator
            .mul_mod(zeta.add_mod(work_root.mul_mod(accumulating_root, p), p), p);

        let lagrange_numerator = vanishing_numerator.mul_mod(domain_inverse, p);
        let l_start_denominator = zeta.add_mod(p_sub_1, p);

        accumulating_root = work_root.mul_mod(work_root, p);
        let l_end_denominator = accumulating_root
            .mul_mod(accumulating_root, p)
            .mul_mod(work_root, p)
            .mul_mod(zeta, p)
            .add_mod(p_sub_1, p);

        let mut accumulator = delta_denominator_root;
        let mut t0 = accumulator;
        accumulator = accumulator.mul_mod(vanishing_denominator, p);
        let mut t1 = accumulator;
        accumulator = accumulator.mul_mod(vanishing_numerator, p);
        let mut t2 = accumulator;
        accumulator = accumulator.mul_mod(l_start_denominator, p);
        let mut t3 = accumulator;
        accumulator = accumulator.mul_mod(plookup_delta_denominator_root, p);
        let mut t4 = accumulator;

        let mod_exp_calldata: Vec<u8> = [
            [0x20, 0x20, 0x20],
            accumulator.mul_mod(l_end_denominator, p).to_le_bytes(),
            p_sub_2.to_le_bytes(),
            p.to_le_bytes(),
        ]
        .concat();
        let result = RawCall::new_static()
            .call(
                address!("0000000000000000000000000000000000000005"),
                &mod_exp_calldata,
            )
            .expect("call should succeed");
        accumulator = U256::from_le_bytes(result.try_into().unwrap());

        t4 = accumulator.mul_mod(t4, p);
        accumulator = accumulator.mul_mod(l_end_denominator, p);

        t3 = accumulator.mul_mod(t3, p);
        accumulator = accumulator.mul_mod(plookup_delta_denominator_root, p);

        t2 = accumulator.mul_mod(t2, p);
        accumulator = accumulator.mul_mod(l_start_denominator, p);

        t1 = accumulator.mul_mod(t1, p);
        accumulator = accumulator.mul_mod(vanishing_numerator, p);

        t0 = accumulator.mul_mod(t0, p);
        accumulator = accumulator.mul_mod(vanishing_denominator, p);

        accumulator = accumulator
            .mul_mod(accumulator, p)
            .mul_mod(delta_denominator_root, p);

        let PUBLIC_INPUT_DELTA = delta_numerator_root.mul_mod(accumulator, p);
        let ZERO_POLY = vanishing_numerator.mul_mod(t0, p);
        let ZERO_POLY_INVERSE = vanishing_denominator.mul_mod(t1, p);
        let L_START = lagrange_numerator.mul_mod(t2, p);
        let PLOOKUP_DELTA = plookup_delta_numerator_root.mul_mod(t3, p);
        let L_END = lagrange_numerator.mul_mod(t4, p);

        Ok((
            ZETA_POW_N_LOC,
            PUBLIC_INPUT_DELTA,
            ZERO_POLY,
            ZERO_POLY_INVERSE,
            L_START,
            PLOOKUP_DELTA,
            L_END,
        ))
    }

    fn compute_permutation_widget_evaluation(alpha: U256, beta: U256, gamma: U256, proof: &Proof) {
        let p = U256::from_str_radix(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap(); // Prime field order

        let t1 = (proof.W1_EVAL_LOC + gamma + beta.mul_mod(proof.ID1_EVAL_LOC, p)).mul_mod(
            proof.W2_EVAL_LOC + gamma + beta.mul_mod(proof.ID2_EVAL_LOC, p),
            p,
        );
        let t2 = (proof.W3_EVAL_LOC + gamma + beta.mul_mod(proof.ID3_EVAL_LOC, p)).mul_mod(
            proof.W4_EVAL_LOC + gamma + beta.mul_mod(proof.ID4_EVAL_LOC, p),
            p,
        );
        let result_1 = alpha.mul_mod(proof.Z_EVAL_LOC.mul_mod(t1.mul_mod(t2, p), p), p);
        let t1 = (proof.W1_EVAL_LOC + gamma + beta.mul_mod(proof.SIGMA1_EVAL_LOC, p)).mul_mod(
            proof.W2_EVAL_LOC + gamma + beta.mul_mod(proof.SIGMA2_EVAL_LOC, p),
            p,
        );
        let t2 = (proof.W3_EVAL_LOC + gamma + beta.mul_mod(proof.SIGMA3_EVAL_LOC, p)).mul_mod(
            proof.W4_EVAL_LOC + gamma + beta.mul_mod(proof.SIGMA4_EVAL_LOC, p),
            p,
        );
        let result_2 = alpha.mul_mod(proof.Z_OMEGA_EVAL_LOC.mul_mod(t1.mul_mod(t2, p), p), p);
        let result = result_1.add_mod(p.wrapping_sub(result_2), p);

    }
}

/// Declare that `Counter` is a contract with the following external methods.
#[external]
impl Verifier {
    /// Gets the number from storage.
    pub fn verify(&self, proof: Vec<u8>, public_inputs: Vec<U256>) -> bool {
        let q = U256::from_str_radix(
            "21888242871839275222246405745257275088696311157297823662689037894645226208583",
            10,
        )
        .unwrap(); // EC group order
        let p = U256::from_str_radix(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap(); // Prime field order

        let proof = Proof::from_bytes(proof);

        // TODO: load recursive proof info.

        let vk = Verifier::vk();

        let initial_challenge =
            keccak([vk.circuit_size.to_le_bytes(), vk.num_inputs.to_le_bytes()].concat());
        let public_inputs_bytes: Vec<u8> = public_inputs
            .into_iter()
            .flat_map(|public_input| public_input.to_vec())
            .collect();

        let eta_challenge_input: Vec<u8> = initial_challenge
            .0
            .to_vec()
            .into_iter()
            .chain(public_inputs_bytes)
            .chain(proof.w1.y.to_le_bytes::<32>())
            .chain(proof.w1.x.to_le_bytes::<32>())
            .chain(proof.w2.y.to_le_bytes::<32>())
            .chain(proof.w2.x.to_le_bytes::<32>())
            .chain(proof.w3.y.to_le_bytes::<32>())
            .chain(proof.w3.x.to_le_bytes::<32>())
            .collect();
        let eta_challenge = keccak(eta_challenge_input);
        let eta_challenge_reduced = U256::from_le_bytes(*eta_challenge).reduce_mod(p);

        let beta_challenge_input: Vec<u8> = eta_challenge
            .0
            .to_vec()
            .into_iter()
            .chain(proof.w4.y.to_le_bytes::<32>())
            .chain(proof.w4.x.to_le_bytes::<32>())
            .chain(proof.s.y.to_le_bytes::<32>())
            .chain(proof.s.x.to_le_bytes::<32>())
            .collect();
        let beta_challenge = keccak(beta_challenge_input);
        let beta_challenge_reduced = U256::from_le_bytes(*beta_challenge).reduce_mod(p);

        let gamma_challenge_input: Vec<u8> = [beta_challenge.0.to_vec(), [0x01].to_vec()].concat();
        let gamma_challenge = keccak(gamma_challenge_input);
        let gamma_challenge_reduced = U256::from_le_bytes(*gamma_challenge).reduce_mod(p);

        let alpha_challenge_input: Vec<u8> = gamma_challenge
            .0
            .to_vec()
            .into_iter()
            .chain(proof.z.y.to_le_bytes::<32>())
            .chain(proof.z.x.to_le_bytes::<32>())
            .chain(proof.z_lookup.y.to_le_bytes::<32>())
            .chain(proof.z_lookup.x.to_le_bytes::<32>())
            .collect();
        let alpha_challenge = keccak(alpha_challenge_input);
        let alpha_challenge_reduced = U256::from_le_bytes(*alpha_challenge).reduce_mod(p);

        //compute some powers

        let zeta_challenge_input: Vec<u8> = alpha_challenge
            .0
            .to_vec()
            .into_iter()
            .chain(proof.t1.y.to_le_bytes::<32>())
            .chain(proof.t1.x.to_le_bytes::<32>())
            .chain(proof.t2.y.to_le_bytes::<32>())
            .chain(proof.t2.x.to_le_bytes::<32>())
            .chain(proof.t3.y.to_le_bytes::<32>())
            .chain(proof.t3.x.to_le_bytes::<32>())
            .chain(proof.t4.y.to_le_bytes::<32>())
            .chain(proof.t4.x.to_le_bytes::<32>())
            .collect();
        let zeta_challenge = keccak(zeta_challenge_input);
        let zeta_challenge_reduced = U256::from_le_bytes(*zeta_challenge).reduce_mod(p);

        // UltraPlonk Widget Ordering:
        //
        // 1. Permutation widget
        // 2. Plookup widget
        // 3. Arithmetic widget
        // 4. Fixed base widget (?)
        // 5. GenPermSort widget
        // 6. Elliptic widget
        // 7. Auxiliary widget

        true
    }
}
