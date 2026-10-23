/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "extern_lib/declaration.p4"

#define COLLECTION_TIMEDELTA 55000

/*
 * p4c limits a header field to 2048 bits, so the application payload is
 * parsed into 256-byte slices (a header stack filled by a parser loop) plus a
 * varbit tail for the last < 256 bytes. 255 slices + a 255-byte tail cover
 * any IPv4 packet; lower this to trade the maximum payload for a smaller PHV.
 */
#define P4ICS_MAX_SLICES 255

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
const bit<16> TYPE_IPV4 = 0x800;

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

// P4ICS trailer of the IPv4 header (IHL 5 -> 13): 32 bytes of "options".
header ipv4_options_t {
    bit<32>  savedLen;  // plaintext length; first byte 0 = IPv4 End of Option List
    bit<32>  spi;       // sender (security association) identifier
    bit<64>  counter;   // per-sender packet counter: anti-replay and IV input
    bit<128> tag;       // HMAC-SHA256-128 over the packet context and the ciphertext
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

// Whatever options the segment carries (dataOffset - 5 words, at most 40 bytes).
header tcp_options_t {
    varbit<320> options;
}

header modbus_tcp_t {
    bit<16> transactionId;
    bit<16> protocolId;
    bit<16> length;
    bit<8> unitId;
}

header mqtt_tcp_t {
    bit<4> packetType;
    bit<4> flags;
    bit<8> length;
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

// Application payload: full 256-byte slices, then the remaining bytes.
header payload_slice_t {
    bit<2048> data;
}

header payload_tail_t {
    varbit<2040> data;
}

const bit<8> PROTO_MODBUS = 1;
const bit<8> PROTO_MQTT = 2;
const bit<8> PROTO_CIP = 3;
const bit<8> PROTO_DNP3 = 4;

struct p4ics_metadata_t {
    bit<8>  proto;
    bit<16> app_len;        // bytes after the TCP header
    bit<16> hdr_len;        // bytes of the industrial protocol header
    bit<17> diff;           // app_len - hdr_len, bit 16 set if negative
    bit<16> payload_len;    // bytes after the industrial header: what P4ICS protects
    bit<16> remaining;      // parser loop counter
    bit<1>  drop;
}

struct metadata {
    p4ics_metadata_t p4ics;
    bit<1> isSec;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv4_options_t ipv4_options;
    tcp_t tcp;
    tcp_options_t tcp_options;
    modbus_tcp_t modbus_tcp;
    mqtt_tcp_t mqtt_tcp;
    cip_tcp_t cip_tcp;
    dnp3_tcp_t dnp3_tcp;
    payload_slice_t[P4ICS_MAX_SLICES] slices;
    payload_tail_t tail;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        meta.isSec = 0;
        meta.p4ics.payload_len = 0;
        meta.p4ics.drop = 0;
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
            13: parse_ipv4_options;
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
        transition select(hdr.tcp.dataOffset) {
            4w0 &&& 4w0xC: accept;     // 0..3: malformed
            4: accept;
            5: parse_tcp_payload_len;
            default: parse_tcp_options;
        }
    }

    state parse_tcp_options {
        packet.extract(hdr.tcp_options, (bit<32>)((((bit<16>)hdr.tcp.dataOffset) << 2) - 20) << 3);
        transition parse_tcp_payload_len;
    }

    // L_app = IPv4.TotalLength - 4 * IPv4.IHL - 4 * TCP.DataOffset
    state parse_tcp_payload_len {
        meta.p4ics.app_len = hdr.ipv4.totalLen - (((bit<16>)hdr.ipv4.ihl) << 2)
                             - (((bit<16>)hdr.tcp.dataOffset) << 2);
        transition select(meta.p4ics.app_len) {
            0 : accept;
            _ : check_dst_port_tcp;
        }
    }

    state check_dst_port_tcp {
        transition select(hdr.tcp.dstPort) {
            502 : proto_modbus;
            1883 : proto_mqtt;
            44818 : proto_cip;
            20000 : proto_dnp3;
            default : check_src_port_tcp;
        }
    }

    state check_src_port_tcp {
        transition select(hdr.tcp.srcPort) {
            502 : proto_modbus;
            1883 : proto_mqtt;
            44818 : proto_cip;
            20000 : proto_dnp3;
            default : accept;
        }
    }

    state proto_modbus {
        meta.p4ics.proto = PROTO_MODBUS;
        meta.p4ics.hdr_len = 7;
        transition check_app_len;
    }

    state proto_mqtt {
        meta.p4ics.proto = PROTO_MQTT;
        meta.p4ics.hdr_len = 2;
        transition check_app_len;
    }

    state proto_cip {
        meta.p4ics.proto = PROTO_CIP;
        meta.p4ics.hdr_len = 24;
        transition check_app_len;
    }

    state proto_dnp3 {
        meta.p4ics.proto = PROTO_DNP3;
        meta.p4ics.hdr_len = 10;
        transition check_app_len;
    }

    // Segments shorter than the protocol header carry no protectable data.
    state check_app_len {
        meta.p4ics.diff = (bit<17>)meta.p4ics.app_len - (bit<17>)meta.p4ics.hdr_len;
        transition select(meta.p4ics.diff[16:16], meta.p4ics.proto) {
            (1, _) : accept;
            (0, PROTO_MODBUS) : extract_modbus_tcp;
            (0, PROTO_MQTT) : extract_mqtt_tcp;
            (0, PROTO_CIP) : extract_cip_tcp;
            (0, PROTO_DNP3) : extract_dnp3_tcp;
            default : accept;
        }
    }

    state extract_modbus_tcp {
        packet.extract(hdr.modbus_tcp);
        transition parse_payload;
    }

    state extract_mqtt_tcp {
        packet.extract(hdr.mqtt_tcp);
        transition parse_payload;
    }

    state extract_cip_tcp {
        packet.extract(hdr.cip_tcp);
        transition parse_payload;
    }

    state extract_dnp3_tcp {
        packet.extract(hdr.dnp3_tcp);
        transition parse_payload;
    }

    state parse_payload {
        meta.p4ics.payload_len = meta.p4ics.diff[15:0];
        meta.p4ics.remaining = meta.p4ics.payload_len;
        transition parse_slices;
    }

    // One 256-byte slice per iteration while at least 256 bytes remain. A
    // payload larger than the stack ends in a StackOutOfBounds parser error,
    // which the ingress turns into a drop for protected ports.
    state parse_slices {
        transition select(meta.p4ics.remaining[15:8]) {
            0 : parse_tail;
            _ : parse_slice;
        }
    }

    state parse_slice {
        packet.extract(hdr.slices.next);
        meta.p4ics.remaining = meta.p4ics.remaining - 256;
        transition parse_slices;
    }

    state parse_tail {
        transition select(meta.p4ics.remaining) {
            0 : accept;
            _ : extract_tail;
        }
    }

    state extract_tail {
        packet.extract(hdr.tail, ((bit<32>)meta.p4ics.remaining) << 3);
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

    // Security association state (set by the control plane, see commands.txt
    // and the switch startup script).
    register<bit<32>>(1) p4ics_spi;          // SPI of this switch as a sender: 1..255, 0 = unset
    register<bit<64>>(1) p4ics_tx_counter;   // last counter sent; startup sets ns since 2020
    register<bit<64>>(256) p4ics_rx_last;    // per sender (SPI & 0xff): highest counter accepted
    register<bit<64>>(256) p4ics_rx_window;  // per sender: bitmap of the 64 counters below it
    // 0: protected, 1: unprotected, 2: rejected (tag/length), 3: rejected (replay)
    counter(4, CounterType.packets) p4ics_events;

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

    // Plaintext -> protected. A segment that is already protected (e.g. by a
    // host that terminates P4ICS itself) is forwarded as is.
    action cipher() {
        if (!hdr.ipv4_options.isValid()) {
            meta.isSec = 1;
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
            bit<256> key = k1 ++ k2 ++ k3 ++ k4 ++ k5 ++ k6 ++ k7 ++ k8;
            bit<32> spi;
            bit<64> tx_counter;
            p4ics_spi.read(spi, 0);
            p4ics_tx_counter.read(tx_counter, 0);
            tx_counter = tx_counter + 1;
            p4ics_tx_counter.write(0, tx_counter);
            hdr.ipv4_options.setValid();
            hdr.ipv4_options.spi = spi;
            hdr.ipv4_options.counter = tx_counter;
            bit<1> done = 0;
            p4ics_cipher(hdr.slices, hdr.tail, hdr.ipv4_options, hdr.ipv4, hdr.tcp,
                         hdr.modbus_tcp, hdr.mqtt_tcp, hdr.cip_tcp, hdr.dnp3_tcp, key, done);
            bit<16> crypt_payload_length = ((meta.p4ics.payload_len >> 4) + 1) << 4;
            bit<32> new_len = (bit<32>)hdr.ipv4.totalLen + (bit<32>)crypt_payload_length
                              - (bit<32>)meta.p4ics.payload_len + 32; //32 is the ipv4 options size in bytes
            hdr.ipv4.ihl = 13;
            hdr.ipv4.totalLen = (bit<16>)new_len;
            // Fail closed: never forward a payload that could not be protected.
            meta.p4ics.drop = (done == 0 || spi == 0 || new_len > 65535) ? 1w1 : 1w0;
            if (meta.p4ics.drop == 0) {
                p4ics_events.count(0);
            }
        }
    }

    // Protected -> plaintext. Dropped unless the HMAC tag verifies (checked
    // before decrypting) and the counter is fresh; also dropped when the
    // segment is not protected at all.
    action decipher() {
        meta.isSec = 1;
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
        bit<256> key = k1 ++ k2 ++ k3 ++ k4 ++ k5 ++ k6 ++ k7 ++ k8;
        bit<1> verified = 0;
        bit<1> fresh = 0;
        if (hdr.ipv4_options.isValid()) {
            p4ics_decipher(hdr.slices, hdr.tail, hdr.ipv4_options, hdr.ipv4, hdr.tcp,
                           hdr.modbus_tcp, hdr.mqtt_tcp, hdr.cip_tcp, hdr.dnp3_tcp, key, verified);
        }
        // Anti-replay window as in IPsec ESP (RFC 4303), updated only for
        // authenticated frames so that forged ones cannot move it.
        if (verified == 1) {
            bit<32> sa = (bit<32>)hdr.ipv4_options.spi[7:0];
            bit<64> last;
            bit<64> window;
            p4ics_rx_last.read(last, sa);
            p4ics_rx_window.read(window, sa);
            bit<64> rx_counter = hdr.ipv4_options.counter;
            if (rx_counter > last) {
                bit<64> ahead = rx_counter - last;
                if (ahead >= 64) {
                    window = 1;
                } else {
                    window = (window << (bit<8>)ahead) | 1;
                }
                last = rx_counter;
                fresh = 1;
            } else {
                bit<64> behind = last - rx_counter;
                if (behind < 64) {
                    bit<64> seen = 64w1 << (bit<8>)behind;
                    if ((window & seen) == 0) {
                        window = window | seen;
                        fresh = 1;
                    }
                }
            }
            p4ics_rx_last.write(sa, last);
            p4ics_rx_window.write(sa, window);
        }
        if (fresh == 1) {
            hdr.ipv4.ihl = 5;
            hdr.ipv4.totalLen = hdr.ipv4.totalLen - meta.p4ics.payload_len
                                + (bit<16>)hdr.ipv4_options.savedLen - 32;
            hdr.ipv4_options.setInvalid();
            p4ics_events.count(1);
        } else if (verified == 1) {
            p4ics_events.count(3);
        } else {
            p4ics_events.count(2);
        }
        meta.p4ics.drop = ~fresh;
    }

    table ics_sec {
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
            if (hdr.tcp.isValid() && meta.p4ics.payload_len != 0){
                if (hdr.modbus_tcp.isValid() || hdr.mqtt_tcp.isValid() || hdr.cip_tcp.isValid() || hdr.dnp3_tcp.isValid()){
                    switch (ics_sec.apply().action_run) {
                        cipher: {
                            if (standard_metadata.parser_error != error.NoError || meta.p4ics.drop == 1) {
                                mark_to_drop(standard_metadata);
                            }
                        }
                        decipher: {
                            if (standard_metadata.parser_error != error.NoError || meta.p4ics.drop == 1) {
                                mark_to_drop(standard_metadata);
                            }
                        }
                    }
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

        if(meta.isSec == 1){
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
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid() && !hdr.ipv4_options.isValid(),
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
        // RFC 791: the checksum also covers the 32 bytes of P4ICS options.
        update_checksum(
            hdr.ipv4.isValid() && hdr.ipv4_options.isValid(),
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
              hdr.ipv4.dstAddr,
              hdr.ipv4_options.savedLen,
              hdr.ipv4_options.spi,
              hdr.ipv4_options.counter,
              hdr.ipv4_options.tag },
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
        packet.emit(hdr.modbus_tcp);
        packet.emit(hdr.mqtt_tcp);
        packet.emit(hdr.cip_tcp);
        packet.emit(hdr.dnp3_tcp);
        packet.emit(hdr.slices);
        packet.emit(hdr.tail);
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
