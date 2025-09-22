/*
    AES-128 encryption in P4
    Copyright (C) 2019 Xiaoqi Chen, Princeton University

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#define COPYRIGHT_STRING 0xA9204147504c7633
//"© AGPLv3"


// Standard headers
#include <core.p4>
#include <v1model.p4>

// AES encryption lookup tables, to fill match-action entries at compile time. You may also fill it in at run time.
#ifndef EMPTY_LUT_FILL_AT_RUNTIME
	#include "LUT.h"
#else
	#define GEN_LUT0(FN) {}
	#define GEN_LUT1(FN) {}
	#define GEN_LUT2(FN) {}
	#define GEN_LUT3(FN) {}
	#define GEN_LUT_SBOX(FN) {}
#endif

#define AES_PORT 502


typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
//const bit<16> IPV4_LEN = 16w20;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;


// We define a special header type to pass in the cleartext & outut ciphertext
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

header modbus_tcp_t {
    bit<16> transactionId;
    bit<16> protocolId;
    bit<16> length;
    bit<8> unitId;
}

#define ETHERTYPE_AES_TOY 0x9999

// We perform one block of AES.
// To perform multiple block using modes like CBC/CTR, etc., simply XOR a counter/IV with value before starting AES.
header aes_inout_t {
    bit<128> value;
    bit<8> ff; // should be 0xFF.
}
header copyright_t {
	bit<64> value;
}

struct my_headers_t {
    ethernet_t   ethernet;
    aes_inout_t     aes_inout;
    copyright_t copy;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    modbus_tcp_t modbus_tcp;
}


header aes_meta_t {
    // internal state, 4 rows
    bit<32> r0;
    bit<32> r1;
    bit<32> r2;
    bit<32> r3;
    // temporary accumulator, for XOR-ing the result of many LUTs
    bit<32> t0;
    bit<32> t1;
    bit<32> t2;
    bit<32> t3;
}


struct my_metadata_t {
    aes_meta_t aes;
}

parser MyParser(
    packet_in                 packet,
    out   my_headers_t    hdr,
    inout my_metadata_t   meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        packet.extract(hdr.ethernet);
        transition select (hdr.ethernet.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);

//        ig_md.tcp_metadata.full_length = (hdr.ipv4.total_len - IPV4_LEN) * 8;
//        ig_md.tcp_metadata.header_length = (((bit<16>)hdr.tcp.data_offset) << 5);
//        ig_md.tcp_metadata.payload_length = ig_md.tcp_metadata.full_length - ig_md.tcp_metadata.header_length;
        transition check_dst_port_tcp;
    }

    state check_dst_port_tcp {
        transition select(hdr.tcp.dst_port){
            AES_PORT: extract_modbus_tcp;
            AES_PORT+1: extract_modbus_tcp;
            default: check_src_port_tcp;
        }
    }

    state check_src_port_tcp {
        transition select(hdr.tcp.src_port){
            AES_PORT: extract_modbus_tcp;
            AES_PORT+1: extract_modbus_tcp;
            default: accept;
        }
    }

    state extract_modbus_tcp {
        packet.extract(hdr.modbus_tcp);
        transition select(hdr.tcp.dst_port) {
            AES_PORT: parse_aes;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            AES_PORT: parse_aes;
            default: accept;
        }
    }  
    
    state parse_aes {
        packet.extract(hdr.aes_inout);
        transition accept;
    }
}

control MyVerifyChecksum(inout my_headers_t hdr, inout my_metadata_t meta) {
    apply { }
}

control MyIngress(
    inout my_headers_t     hdr,
    inout my_metadata_t    meta,
    inout standard_metadata_t  standard_metadata)
{
    action reflect() {
        bit<48> tmp;
        // Reflect the packet back to sender.
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;
		hdr.copy.setValid();
		hdr.copy.value=COPYRIGHT_STRING;
    }

    action _drop() {
        mark_to_drop(standard_metadata);
    }

	// ===== Start of AES logic =====

	action read_cleartext(){
		meta.aes.t0=hdr.aes_inout.value[127:96];
		meta.aes.t1=hdr.aes_inout.value[95:64];
		meta.aes.t2=hdr.aes_inout.value[63:32];
		meta.aes.t3=hdr.aes_inout.value[31:0];
	}

	action mask_key(bit<128> key128){
		meta.aes.r0= meta.aes.t0^key128[127:96];
		meta.aes.r1= meta.aes.t1^key128[95:64];
		meta.aes.r2= meta.aes.t2^key128[63:32];
		meta.aes.r3= meta.aes.t3^key128[31:0];
	}

	action write_ciphertext(){
		hdr.aes_inout.value[127:96]=meta.aes.r0;
		hdr.aes_inout.value[95:64]=meta.aes.r1;
		hdr.aes_inout.value[63:32]=meta.aes.r2;
		hdr.aes_inout.value[31:0]=meta.aes.r3;

	}

#define TABLE_MASK_KEY(ROUND,SUBKEY128) table mask_key_round_##ROUND { \
		actions = {mask_key;} \
		default_action = mask_key(SUBKEY128); \
	}
// For demonstration purpose, here we put in all the 10-round subkeys derived from an example key 0x01010101020202020303030304040404
//	TABLE_MASK_KEY( 0,0x01010101020202020303030304040404)
//	TABLE_MASK_KEY( 1,0xf2f3f3f3f0f1f1f1f3f2f2f2f7f6f6f6)
//	TABLE_MASK_KEY( 2,0xb2b1b19b4240406ab1b2b2984644446e)
//	TABLE_MASK_KEY( 3,0xadaa2ec1efea6eab5e58dc33181c985d)
//	TABLE_MASK_KEY( 4,0x39ec626cd6060cc7885ed0f4904248a9)
//	TABLE_MASK_KEY( 5,0x5beb10cd3b8bdcb5be66d3fcba42596)
//	TABLE_MASK_KEY( 6,0x6c812113bf399cd8e4dff1e72f7bd471)
//	TABLE_MASK_KEY( 7,0xdc98206b2f01ede562fef3979543b48)
//	TABLE_MASK_KEY( 8,0xad2bd0b01fdbce6e49f4215730a01a1f)
//	TABLE_MASK_KEY( 9,0x568910b44952deda00a6ff8d3006e592)
//	TABLE_MASK_KEY(10,0xf505fb04602816a46a47ee776a29b75)

	TABLE_MASK_KEY( 0,0x000102030405060708090a0b0c0d0e0f)
	TABLE_MASK_KEY( 1,0xd6aa74fdd2af72fadaa678f1d6ab76fe)
	TABLE_MASK_KEY( 2,0xb692cf0b643dbdf1be9bc5006830b3fe)
	TABLE_MASK_KEY( 3,0xb6ff744ed2c2c9bf6c590cbf0469bf41)
	TABLE_MASK_KEY( 4,0x47f7f7bc95353e03f96c32bcfd058dfd)
	TABLE_MASK_KEY( 5,0x3caaa3e8a99f9deb50f3af57adf622aa)
	TABLE_MASK_KEY( 6,0x5e390f7df7a69296a7553dc10aa31f6b)
	TABLE_MASK_KEY( 7,0x14f9701ae35fe28c440adf4d4ea9c026)
	TABLE_MASK_KEY( 8,0x47438735a41c65b9e016baf4aebf7ad2)
	TABLE_MASK_KEY( 9,0x549932d1f08557681093ed9cbe2c974e)
	TABLE_MASK_KEY(10,0x13111d7fe3944a17f307a78b4d2b30c5)


#define APPLY_MASK_KEY(ROUND) mask_key_round_##ROUND##.apply();


	action new_round() {
		// Could be skipped, if we use better renaming and read key first.
		// We do this for the sake of code tidyness. More efficient implementation possible, using fewer hardware stages.
		meta.aes.t0=0;  meta.aes.t1=0;  meta.aes.t2=0;  meta.aes.t3=0;
	}

// Macros for defining actions, XOR value from LUT to accummulator variable

#define merge_to(T) action merge_to_t##T##(bit<32> val){\
		meta.aes.t##T##=meta.aes.t##T##^val;	\
	}
	merge_to(0)
	merge_to(1)
	merge_to(2)
	merge_to(3)

// XOR value from LUT to a slice of accummulator variable
#define merge_to_partial(T,SLICE,SLICE_BITS)  action merge_to_t##T##_slice##SLICE##(bit<8> val){ \
	meta.aes.t##T##SLICE_BITS##=meta.aes.t##T##SLICE_BITS##^val;\
	}
	merge_to_partial(0,0,[31:24])
	merge_to_partial(0,1,[23:16])
	merge_to_partial(0,2,[15: 8])
	merge_to_partial(0,3,[ 7: 0])
	merge_to_partial(1,0,[31:24])
	merge_to_partial(1,1,[23:16])
	merge_to_partial(1,2,[15: 8])
	merge_to_partial(1,3,[ 7: 0])
	merge_to_partial(2,0,[31:24])
	merge_to_partial(2,1,[23:16])
	merge_to_partial(2,2,[15: 8])
	merge_to_partial(2,3,[ 7: 0])
	merge_to_partial(3,0,[31:24])
	merge_to_partial(3,1,[23:16])
	merge_to_partial(3,2,[15: 8])
	merge_to_partial(3,3,[ 7: 0])

// Macros for defining lookup tables, which is match-action table that XOR the value into accumulator variable
#define TABLE_LUT(NAME,READ,WHICH_LUT,WRITE) table NAME { \
		key= {READ:exact;}\
		actions = {WRITE;}\
		const entries = WHICH_LUT(WRITE)\
		}

#define LUT00(ROUND)	TABLE_LUT(aes_sbox_lut_00_r##ROUND, meta.aes.r0[31:24], GEN_LUT0, merge_to_t0)
#define LUT01(ROUND)	TABLE_LUT(aes_sbox_lut_01_r##ROUND, meta.aes.r1[23:16], GEN_LUT1, merge_to_t0)
#define LUT02(ROUND)	TABLE_LUT(aes_sbox_lut_02_r##ROUND, meta.aes.r2[15: 8], GEN_LUT2, merge_to_t0)
#define LUT03(ROUND)	TABLE_LUT(aes_sbox_lut_03_r##ROUND, meta.aes.r3[7 : 0], GEN_LUT3, merge_to_t0)

#define LUT10(ROUND)	TABLE_LUT(aes_sbox_lut_10_r##ROUND, meta.aes.r1[31:24], GEN_LUT0, merge_to_t1)
#define LUT11(ROUND)	TABLE_LUT(aes_sbox_lut_11_r##ROUND, meta.aes.r2[23:16], GEN_LUT1, merge_to_t1)
#define LUT12(ROUND)	TABLE_LUT(aes_sbox_lut_12_r##ROUND, meta.aes.r3[15: 8], GEN_LUT2, merge_to_t1)
#define LUT13(ROUND)	TABLE_LUT(aes_sbox_lut_13_r##ROUND, meta.aes.r0[7 : 0], GEN_LUT3, merge_to_t1)

#define LUT20(ROUND)	TABLE_LUT(aes_sbox_lut_20_r##ROUND, meta.aes.r2[31:24], GEN_LUT0, merge_to_t2)
#define LUT21(ROUND)	TABLE_LUT(aes_sbox_lut_21_r##ROUND, meta.aes.r3[23:16], GEN_LUT1, merge_to_t2)
#define LUT22(ROUND)	TABLE_LUT(aes_sbox_lut_22_r##ROUND, meta.aes.r0[15: 8], GEN_LUT2, merge_to_t2)
#define LUT23(ROUND)	TABLE_LUT(aes_sbox_lut_23_r##ROUND, meta.aes.r1[7 : 0], GEN_LUT3, merge_to_t2)

#define LUT30(ROUND)	TABLE_LUT(aes_sbox_lut_30_r##ROUND, meta.aes.r3[31:24], GEN_LUT0, merge_to_t3)
#define LUT31(ROUND)	TABLE_LUT(aes_sbox_lut_31_r##ROUND, meta.aes.r0[23:16], GEN_LUT1, merge_to_t3)
#define LUT32(ROUND)	TABLE_LUT(aes_sbox_lut_32_r##ROUND, meta.aes.r1[15: 8], GEN_LUT2, merge_to_t3)
#define LUT33(ROUND)	TABLE_LUT(aes_sbox_lut_33_r##ROUND, meta.aes.r2[7 : 0], GEN_LUT3, merge_to_t3)

// We need one copy of all tables for each round. Otherwise, there's dependency issue...
#define GENERATE_ALL_TABLE_LUT(ROUND) LUT00(ROUND) LUT01(ROUND) LUT02(ROUND) LUT03(ROUND) LUT10(ROUND) LUT11(ROUND) LUT12(ROUND) LUT13(ROUND) LUT20(ROUND) LUT21(ROUND) LUT22(ROUND) LUT23(ROUND) LUT30(ROUND) LUT31(ROUND) LUT32(ROUND) LUT33(ROUND)
GENERATE_ALL_TABLE_LUT(1)
GENERATE_ALL_TABLE_LUT(2)
GENERATE_ALL_TABLE_LUT(3)
GENERATE_ALL_TABLE_LUT(4)
GENERATE_ALL_TABLE_LUT(5)
GENERATE_ALL_TABLE_LUT(6)
GENERATE_ALL_TABLE_LUT(7)
GENERATE_ALL_TABLE_LUT(8)
GENERATE_ALL_TABLE_LUT(9)
//Only round 1-9 requires mixcolumns. round 10 is different:
// LAST round is special, use SBOX directly as LUT
	TABLE_LUT(aes_sbox_lut_00_rLAST, meta.aes.r0[31:24], GEN_LUT_SBOX, merge_to_t0_slice0)
	TABLE_LUT(aes_sbox_lut_01_rLAST, meta.aes.r1[23:16], GEN_LUT_SBOX, merge_to_t0_slice1)
	TABLE_LUT(aes_sbox_lut_02_rLAST, meta.aes.r2[15: 8], GEN_LUT_SBOX, merge_to_t0_slice2)
	TABLE_LUT(aes_sbox_lut_03_rLAST, meta.aes.r3[7 : 0], GEN_LUT_SBOX, merge_to_t0_slice3)

	TABLE_LUT(aes_sbox_lut_10_rLAST, meta.aes.r1[31:24], GEN_LUT_SBOX, merge_to_t1_slice0)
	TABLE_LUT(aes_sbox_lut_11_rLAST, meta.aes.r2[23:16], GEN_LUT_SBOX, merge_to_t1_slice1)
	TABLE_LUT(aes_sbox_lut_12_rLAST, meta.aes.r3[15: 8], GEN_LUT_SBOX, merge_to_t1_slice2)
	TABLE_LUT(aes_sbox_lut_13_rLAST, meta.aes.r0[7 : 0], GEN_LUT_SBOX, merge_to_t1_slice3)

	TABLE_LUT(aes_sbox_lut_20_rLAST, meta.aes.r2[31:24], GEN_LUT_SBOX, merge_to_t2_slice0)
	TABLE_LUT(aes_sbox_lut_21_rLAST, meta.aes.r3[23:16], GEN_LUT_SBOX, merge_to_t2_slice1)
	TABLE_LUT(aes_sbox_lut_22_rLAST, meta.aes.r0[15: 8], GEN_LUT_SBOX, merge_to_t2_slice2)
	TABLE_LUT(aes_sbox_lut_23_rLAST, meta.aes.r1[7 : 0], GEN_LUT_SBOX, merge_to_t2_slice3)

	TABLE_LUT(aes_sbox_lut_30_rLAST, meta.aes.r3[31:24], GEN_LUT_SBOX, merge_to_t3_slice0)
	TABLE_LUT(aes_sbox_lut_31_rLAST, meta.aes.r0[23:16], GEN_LUT_SBOX, merge_to_t3_slice1)
	TABLE_LUT(aes_sbox_lut_32_rLAST, meta.aes.r1[15: 8], GEN_LUT_SBOX, merge_to_t3_slice2)
	TABLE_LUT(aes_sbox_lut_33_rLAST, meta.aes.r2[7 : 0], GEN_LUT_SBOX, merge_to_t3_slice3)

#define AP(ROUND,i)  aes_sbox_lut_##i##_r##ROUND##.apply();
#define APPLY_ALL_TABLE_LUT(ROUND) AP(ROUND,00) AP(ROUND,01) AP(ROUND,02) AP(ROUND,03) AP(ROUND,10) AP(ROUND,11) AP(ROUND,12) AP(ROUND,13) AP(ROUND,20) AP(ROUND,21) AP(ROUND,22) AP(ROUND,23) AP(ROUND,30) AP(ROUND,31) AP(ROUND,32) AP(ROUND,33)

	// ==== End of AES LUTs, start of contorl logic ====

    apply {
        if (hdr.aes_inout.isValid() && hdr.aes_inout.ff==0xFF) {
        		read_cleartext();
			// Start AES
			APPLY_MASK_KEY(0);
			// 10-1 Rounds
			new_round(); APPLY_ALL_TABLE_LUT(1); APPLY_MASK_KEY(1);
			new_round(); APPLY_ALL_TABLE_LUT(2); APPLY_MASK_KEY(2);
			new_round(); APPLY_ALL_TABLE_LUT(3); APPLY_MASK_KEY(3);
			new_round(); APPLY_ALL_TABLE_LUT(4); APPLY_MASK_KEY(4);
			new_round(); APPLY_ALL_TABLE_LUT(5); APPLY_MASK_KEY(5);
			new_round(); APPLY_ALL_TABLE_LUT(6); APPLY_MASK_KEY(6);
			new_round(); APPLY_ALL_TABLE_LUT(7); APPLY_MASK_KEY(7);
			new_round(); APPLY_ALL_TABLE_LUT(8); APPLY_MASK_KEY(8);
			new_round(); APPLY_ALL_TABLE_LUT(9); APPLY_MASK_KEY(9);
			// one last round, S-box only
			new_round(); APPLY_ALL_TABLE_LUT(LAST); APPLY_MASK_KEY(10);
			// End AES

			write_ciphertext();
			// Send the packet back to the sender (for debug only).
			reflect();
        } else {
            _drop();
        }
    }
}

control MyEgress(
    inout my_headers_t        hdr,
    inout my_metadata_t       meta,
    inout standard_metadata_t standard_metadata) {
    
    register<bit<48>>(100000) packet_processing_time_array; //egress timestamp - ingress timestamp
    register<bit<32>>(100000) packet_dequeuing_timedelta_array; //deq_timedelta

    register<bit<48>>(1) timestamp_last_seen_packet;
    register<bit<32>>(1) last_saved_index;
    bit<48> diff_time;
    bit<48> last_time;
    bit<32> current_index;


    apply {
        timestamp_last_seen_packet.read(last_time,     0);

        diff_time = standard_metadata.ingress_global_timestamp - last_time;

        //retrieve index
        last_saved_index.read(current_index,     0);

        //retrieve packet processing time
        packet_processing_time_array.write(current_index,
            standard_metadata.egress_global_timestamp-standard_metadata.ingress_global_timestamp);

        //retrieve dequeue timedelta
        packet_dequeuing_timedelta_array.write(current_index,
            standard_metadata.deq_timedelta);

        //update index
        last_saved_index.write(0,     current_index + 1);

        //reset time window
        timestamp_last_seen_packet.write(0,     standard_metadata.ingress_global_timestamp);
    }
}

control MyComputeChecksum(
    inout my_headers_t  hdr,
    inout my_metadata_t meta)
{
    apply {   }
}

control MyDeparser(
    packet_out      packet,
    in my_headers_t hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.modbus_tcp);
        packet.emit(hdr.aes_inout);
        packet.emit(hdr.copy);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;