import pandas as pd
import numpy as np

def map_live_flow(live_flow: dict) -> dict:
    """
    Translates live network flow features (e.g., from netflower/CICFlowMeter)
    into the exact 34 UNSW-NB15 features the model expects.
    """
    
    # Helper function to safely get values and handle None/NaN
    def get_val(keys, default=0):
        for key in keys:
            if key in live_flow and live_flow[key] is not None:
                return live_flow[key]
        return default

    # Build the mapped dictionary
    mapped = {
        # 1. Basic Flow Features
        'dur': get_val(['Flow Duration', 'flow_duration'], 0),
        
        # Note: netflower outputs protocol as TCP/UDP, but UNSW expects 'tcp', 'udp', 'arp', etc.
        'proto': str(get_val(['Protocol', 'protocol'], 'tcp')).lower(),
        
        # Service and State are often missing in raw flows. We default to common values.
        'service': get_val(['Service', 'service'], '-'), 
        'state': get_val(['Connection State', 'state'], 'INT'),

        # 2. Packet Counts
        'spkts': get_val(['Total Fwd Packets', 'fwd_packet_count'], 0), # Source packets
        'dpkts': get_val(['Total Backward Packets', 'bwd_packet_count'], 0), # Destination packets
        'sbytes': get_val(['Total Length of Fwd Packets', 'fwd_byte_count'], 0),
        'dbytes': get_val(['Total Length of Bwd Packets', 'bwd_byte_count'], 0),

        # 3. Rates and Loads
        'rate': get_val(['Flow Packets/s', 'flow_packets_per_sec'], 0),
        'sload': get_val(['Fwd Packets/s', 'fwd_packets_per_sec'], 0), # Approximate
        'dload': get_val(['Bwd Packets/s', 'bwd_packets_per_sec'], 0), # Approximate

        # 4. Loss
        'sloss': get_val(['Fwd Packet Loss', 'fwd_loss'], 0),
        'dloss': get_val(['Bwd Packet Loss', 'bwd_loss'], 0),

        # 5. Inter-arrival times and Jitter
        'sinpkt': get_val(['Fwd Inter-Arrival Time Mean', 'fwd_iat_mean'], 0),
        'dinpkt': get_val(['Bwd Inter-Arrival Time Mean', 'bwd_iat_mean'], 0),
        'sjit': get_val(['Fwd Jitter', 'fwd_jitter'], 0),
        'djit': get_val(['Bwd Jitter', 'bwd_jitter'], 0),

        # 6. TCP Specifics (Defaults to 0 if not found)
        'swin': get_val(['Fwd Init Win Bytes', 'fwd_init_window'], 0),
        'stcpb': get_val(['Fwd TCP Base', 'fwd_tcp_base'], 0),
        'dtcpb': get_val(['Bwd TCP Base', 'bwd_tcp_base'], 0),
        'dwin': get_val(['Bwd Init Win Bytes', 'bwd_init_window'], 0),
        'tcprtt': get_val(['TCP RTT', 'tcp_rtt'], 0),
        'synack': get_val(['SYN ACK', 'syn_ack'], 0),
        'ackdat': get_val(['ACK DAT', 'ack_dat'], 0),

        # 7. Packet Length
        'smean': get_val(['Fwd Packet Length Mean', 'fwd_packet_length_mean'], 0),
        'dmean': get_val(['Bwd Packet Length Mean', 'bwd_packet_length_mean'], 0),

        # 8. Application specific (Rarely captured in live simple flows, default to 0)
        'trans_depth': get_val(['Transaction Depth', 'trans_depth'], 0),
        'response_body_len': get_val(['Response Body Length', 'response_body_len'], 0),
        'ct_src_dport_ltm': get_val(['ct_src_dport_ltm'], 0),
        'ct_dst_sport_ltm': get_val(['ct_dst_sport_ltm'], 0),
        'is_ftp_login': get_val(['is_ftp_login'], 0),
        'ct_ftp_cmd': get_val(['ct_ftp_cmd'], 0),
        'ct_flw_http_mthd': get_val(['ct_flw_http_mthd'], 0),
        'is_sm_ips_ports': get_val(['is_sm_ips_ports'], 0),
    }

    # Convert to DataFrame to ensure column order matches the model
    df = pd.DataFrame([mapped])
    
    # Ensure we only return the 34 columns the model expects
    expected_cols = [
        'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate',
        'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin',
        'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 'smean', 'dmean',
        'trans_depth', 'response_body_len', 'ct_src_dport_ltm', 'ct_dst_sport_ltm',
        'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'is_sm_ips_ports'
    ]
    return df[expected_cols]