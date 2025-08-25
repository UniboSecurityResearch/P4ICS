/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "extern_lib/declaration.p4"

#define COLLECTION_TIMEDELTA 55000

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> IPV4_LEN = 16w20;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv4_options_t {
    bit<32> savedLen;
    bit<256> sha;
}

header sha_temp_store_t {
    bit<32> equals;
    bit<256> shaCalculated;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header tcp_options_t {
    bit<8> nop;
    bit<8> nop2;
    bit<80> timestamps;
} //Due to pymodbus implementation

header tcp_options2_t {
    bit<32> maxSegmentSize;
    bit<16> sackPermitted;
    bit<80> timestamps;
    bit<8> nop;
    bit<24> windowScale;
}//Due to java dnp3 implementation

header modbus_tcp_t {
    bit<16> transactionId;
    bit<16> protocolId;
    bit<16> length;
    bit<8> unitId;
}

header mqtt_tcp_t {
    bit<4> packetType;
    bit<4> flags;
    bit<8> length;//if 0, there are no data in the tcp packet after this value
}

header cip_tcp_t {
    bit<16> command;
    bit<16> length;
    bit<32> sessionHandle;
    bit<32> status;
    bit<64> senderContext;
    bit<32> options;
}

header dnp3_tcp_t {
    bit<16> sync;
    bit<8> length;
    bit<8> linkControl;
    bit<16> destination;
    bit<16> source;
    bit<16> checksum;
}

header payload_t {
   varbit<2048> content;
}

header payload_encrypt_t {
   bit<2048> content;
}

header payload_decrypt_t {
   bit<2048> content;
}
//the size of fields payload_decrypt_t and payload_encrypt_t must be set in definition.cpp (max_size_content) divided by 8

struct tcp_metadata_t
{
    bit<16> full_length; //ipv4.totalLen - 20
    bit<16> full_length_in_bytes;
    bit<16> header_length;
    bit<16> header_length_in_bytes;
    bit<16> payload_length;
    bit<16> payload_length_in_bytes;
}

struct metadata {
    tcp_metadata_t tcp_metadata;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv4_options_t ipv4_options;
    tcp_t tcp;
    tcp_options_t tcp_options;
    tcp_options2_t tcp_options2;
    modbus_tcp_t modbus_tcp;
    mqtt_tcp_t mqtt_tcp;
    cip_tcp_t cip_tcp;
    dnp3_tcp_t dnp3_tcp;
    payload_t payload;
    payload_encrypt_t payload_encrypt;
    payload_decrypt_t payload_decrypt;
    sha_temp_store_t temp;
} //modify payload for modbus


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
       transition parse_ethernet;
    }

     state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl) {
            5: no_parse_ipv4_options;
            14: parse_ipv4_options;
            _ : accept;    // For other protocols, skip to accept
        }
    }

    state parse_ipv4_options {
        packet.extract(hdr.ipv4_options);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;  // Protocol 6 corresponds to TCP
            _ : accept;    // For other protocols, skip to accept
        }
    }

    state no_parse_ipv4_options {
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;  // Protocol 6 corresponds to TCP
            _ : accept;    // For other protocols, skip to accept
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);

        meta.tcp_metadata.full_length = (hdr.ipv4.totalLen - IPV4_LEN) * 8;
        meta.tcp_metadata.header_length = (((bit<16>)hdr.tcp.dataOffset) << 5);
        meta.tcp_metadata.payload_length = meta.tcp_metadata.full_length - meta.tcp_metadata.header_length;

        // meta.tcp_metadata.full_length_in_bytes =  (hdr.ipv4.totalLen - IPV4_LEN);
        // meta.tcp_metadata.header_length_in_bytes = (bit<16>)hdr.tcp.dataOffset << 2;
        // meta.tcp_metadata.payload_length_in_bytes = (hdr.ipv4.totalLen - IPV4_LEN) - ((bit<16>)hdr.tcp.dataOffset << 2);

        transition select(meta.tcp_metadata.payload_length) {
            0 : accept;
            _ : check_dst_port_tcp;
        }
    }

    state check_dst_port_tcp {
        transition select(hdr.tcp.dstPort) {
            502 : extract_modbus_tcp;
            1883 : extract_mqtt_tcp;
            44818 : extract_cip_tcp;
            20000 : extract_dnp3_tcp;
            default : check_src_port_tcp;
        }
    }

    state check_src_port_tcp {
        transition select(hdr.tcp.srcPort) {
            502 : extract_modbus_tcp;
            1883 : extract_mqtt_tcp;
            44818 : extract_cip_tcp;
            20000 : extract_dnp3_tcp;
            default : accept;
        }
    }

    state extract_modbus_tcp {
        packet.extract(hdr.tcp_options);
        packet.extract(hdr.modbus_tcp);
        transition select(hdr.modbus_tcp.length) {
           1: accept;
           _: parse_payload_modbus;
        }
    }

    state extract_mqtt_tcp {
        packet.extract(hdr.tcp_options);
        packet.extract(hdr.mqtt_tcp);
        transition select(hdr.mqtt_tcp.length) {
           0: accept;
           _: parse_payload_mqtt;
        }
    }

    state extract_cip_tcp {
        packet.extract(hdr.tcp_options);
        packet.extract(hdr.cip_tcp);
        transition select(hdr.cip_tcp.length) {
           0: accept;
           _: parse_payload_cip_tcp;
        }
    }

    state extract_dnp3_tcp {
        transition select(hdr.tcp.syn) {
           0: extract_dnp3_tcp_opt1;
           1: extract_dnp3_tcp_opt2;
        }
    }

    state extract_dnp3_tcp_opt1 {
        packet.extract(hdr.tcp_options);
        transition extract_dnp3_tcp_opt;
    }

    state extract_dnp3_tcp_opt2 {
        packet.extract(hdr.tcp_options2);
        transition extract_dnp3_tcp_opt;
    }

    state extract_dnp3_tcp_opt {
        packet.extract(hdr.dnp3_tcp);
        transition select(hdr.dnp3_tcp.length) {
           0: accept;
           _: parse_payload_dnp3_tcp;
        }
    }

    state parse_payload_modbus {
        bit<32> calculated_length = (bit<32>)((hdr.ipv4.totalLen - (((bit<16>)hdr.ipv4.ihl) * 4) - (((bit<16>)hdr.tcp.dataOffset) * 4) - 7) * 8);
        packet.extract(hdr.payload, (bit<32>)(calculated_length));
        transition accept;
    }

    state parse_payload_mqtt {
        bit<32> calculated_length = (bit<32>)((hdr.ipv4.totalLen - (((bit<16>)hdr.ipv4.ihl) * 4) - (((bit<16>)hdr.tcp.dataOffset) * 4) - 2) * 8);
        packet.extract(hdr.payload, (bit<32>)(calculated_length));
        transition accept;
    }

    state parse_payload_cip_tcp {
        bit<32> calculated_length = (bit<32>)((hdr.ipv4.totalLen - (((bit<16>)hdr.ipv4.ihl) * 4) - (((bit<16>)hdr.tcp.dataOffset) * 4) - 24) * 8);
        packet.extract(hdr.payload, (bit<32>)(calculated_length));
        transition accept;
    }

    state parse_payload_dnp3_tcp {
        bit<32> calculated_length = (bit<32>)((hdr.ipv4.totalLen - (((bit<16>)hdr.ipv4.ihl) * 4) - (((bit<16>)hdr.tcp.dataOffset) * 4) - 10) * 8);
        packet.extract(hdr.payload, (bit<32>)(calculated_length));
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

   register<bit<32>>(8) keys;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action no_cipher(){
    }

    action cipher() {
        hdr.payload_encrypt.setValid();
        hdr.ipv4_options.setValid();
        bit<32> k1; bit<32> k2; bit<32> k3; bit<32> k4;
        bit<32> k5; bit<32> k6; bit<32> k7; bit<32> k8;
        keys.read(k1, 0);
        keys.read(k2, 1);
        keys.read(k3, 2);
        keys.read(k4, 3);
        keys.read(k5, 4);
        keys.read(k6, 5);
        keys.read(k7, 6);
        keys.read(k8, 7);
        bit<16> useful_length_fixed = 0;
        if(hdr.modbus_tcp.isValid()) {
            useful_length_fixed = hdr.modbus_tcp.length - 1;
        } else if(hdr.mqtt_tcp.isValid()) {
            useful_length_fixed = (bit<16>)(hdr.ipv4.totalLen - (((bit<16>)hdr.ipv4.ihl) * 4) - (((bit<16>)hdr.tcp.dataOffset) * 4) - 2);
        } else if(hdr.cip_tcp.isValid()) {
            useful_length_fixed = (bit<16>)hdr.cip_tcp.length;
        } else if(hdr.dnp3_tcp.isValid()) {
            useful_length_fixed = (bit<16>)hdr.dnp3_tcp.length - 3;
        }
        hdr.ipv4_options.savedLen = (bit<32>)useful_length_fixed;
        sha256_hash_1024(hdr.ipv4_options.sha, k1, k2, hdr.tcp.seqNo, hdr.payload.content, useful_length_fixed);
        hdr.ipv4.ihl = 14;
        Encrypt(hdr.payload.content, hdr.payload_encrypt.content, k1, k2, k3, k4, k5, k6, k7, k8, useful_length_fixed);
        bit<16> crypt_payload_length = ((useful_length_fixed / 16) + 1) * 16;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - useful_length_fixed + crypt_payload_length + 36; //36 is the ipv4 options size in bytes
        hdr.payload.setInvalid();
    }

    action decipher() {
        hdr.payload_decrypt.setValid();
        bit<32> k1; bit<32> k2; bit<32> k3; bit<32> k4;
        bit<32> k5; bit<32> k6; bit<32> k7; bit<32> k8;
        keys.read(k1, 0);
        keys.read(k2, 1);
        keys.read(k3, 2);
        keys.read(k4, 3);
        keys.read(k5, 4);
        keys.read(k6, 5);
        keys.read(k7, 6);
        keys.read(k8, 7);
        bit<16> useful_length_fixed = 0;
        if (hdr.modbus_tcp.isValid()) {
            useful_length_fixed = hdr.modbus_tcp.length - 1;
        } else if (hdr.mqtt_tcp.isValid()) {
            useful_length_fixed = (bit<16>)hdr.ipv4_options.savedLen;
        } else if (hdr.cip_tcp.isValid()) {
            useful_length_fixed = (bit<16>)hdr.cip_tcp.length;
        } else if (hdr.dnp3_tcp.isValid()) {
            useful_length_fixed = (bit<16>)hdr.dnp3_tcp.length - 3;
        }
        hdr.temp.setValid();
        Decrypt(hdr.payload.content, hdr.payload_decrypt.content, k1, k2, k3, k4, k5, k6, k7, k8, useful_length_fixed, hdr.ipv4_options.sha, hdr.tcp.seqNo, hdr.temp.shaCalculated);//check metadata
        hdr.ipv4.ihl = 5;
        bit<16> crypt_payload_length = ((useful_length_fixed / 16) + 1) * 16;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - crypt_payload_length + useful_length_fixed - 36;
        verify_hash_equals(hdr.temp.equals, hdr.ipv4_options.sha, hdr.temp.shaCalculated);
        hdr.temp.setInvalid();
        hdr.payload.setInvalid();
        hdr.ipv4_options.setInvalid();
    }

    table modbus_sec {
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            no_cipher;
            cipher;
            decipher;
        }
        size = 2;
        default_action = no_cipher();
    }

    apply {
        if (hdr.ipv4.isValid()){
            ipv4_lpm.apply();
            if (hdr.tcp.isValid()){
                if (hdr.modbus_tcp.isValid() || hdr.mqtt_tcp.isValid() || hdr.cip_tcp.isValid() || hdr.dnp3_tcp.isValid()){
                    modbus_sec.apply();
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
                    //apply{}
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

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4_options);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_options);
        packet.emit(hdr.tcp_options2);
        packet.emit(hdr.modbus_tcp);
        packet.emit(hdr.mqtt_tcp);
        packet.emit(hdr.cip_tcp);
        packet.emit(hdr.dnp3_tcp);
        packet.emit(hdr.payload_encrypt);
        packet.emit(hdr.payload_decrypt);
        packet.emit(hdr.payload);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;

