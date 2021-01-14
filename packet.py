from typing import NamedTuple

class ethr_hdr(NamedTuple):
    dst_addr: str
    src_addr: str
    etype: int 

class ip_hdr(NamedTuple):
    version: int
    header_len: int
    type_service: str
    explicit_congestion: str
    total_len: int
    id_num: int
    flags: str
    frag_offset: int
    ttl: int
    protocol: str
    checksum: int
    src_addr: str
    dst_addr: str

class ipv6_hdr(NamedTuple):
    version: int
    dscp: str
    ecn: str
    flow_label: int
    payload_len: int
    next_header: str
    hop_limit: int
    src_addr: str
    dst_addr: str

class tcp_hdr(NamedTuple):
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    offset: int
    flags: str
    window_size: int
    checksum: int
    urg_pointer: int