"""
preprocessor.py
---------------
Loads the fitted StandardScaler and LabelEncoder from disk at import time.

preprocess(record)  ->  np.ndarray of shape (1, 183), dtype float32
"""

import os
import joblib
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Artefact paths
# ---------------------------------------------------------------------------
_BASE = os.path.join(os.path.dirname(__file__), "models_dir")
_SCALER_PATH = os.path.join(_BASE, "scaler(1).pkl")
_LE_PATH     = os.path.join(_BASE, "label_encoder(1).pkl")

# ---------------------------------------------------------------------------
# Load artefacts once at import time
# ---------------------------------------------------------------------------
scaler        = joblib.load(_SCALER_PATH)
label_encoder = joblib.load(_LE_PATH)

# ---------------------------------------------------------------------------
# Feature specification
# ---------------------------------------------------------------------------

# The 32 raw numerical columns (must be scaled)
NUMERICAL_COLS = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
    "sload", "dload", "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb",
    "dtcpb", "dwin", "smean", "dmean", "ct_srv_src", "ct_state_ttl",
    "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm",
    "ct_srv_dst", "is_sm_ips_ports",
]

# The 3 categorical columns to one-hot encode
CATEGORICAL_COLS = ["proto", "service", "state"]

# Exact 183-column feature list that the model expects (order matters)
FEATURE_COLUMNS = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl',
    'sload', 'dload', 'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin', 'stcpb',
    'dtcpb', 'dwin', 'smean', 'dmean', 'ct_srv_src', 'ct_state_ttl',
    'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm',
    'ct_srv_dst', 'is_sm_ips_ports',
    # proto one-hot (130 categories)
    'proto_3pc', 'proto_a/n', 'proto_aes-sp3-d', 'proto_any', 'proto_argus',
    'proto_aris', 'proto_arp', 'proto_ax.25', 'proto_bbn-rcc', 'proto_bna',
    'proto_br-sat-mon', 'proto_cbt', 'proto_cftp', 'proto_chaos',
    'proto_compaq-peer', 'proto_cphb', 'proto_cpnx', 'proto_crtp',
    'proto_crudp', 'proto_dcn', 'proto_ddp', 'proto_ddx', 'proto_dgp',
    'proto_egp', 'proto_eigrp', 'proto_emcon', 'proto_encap', 'proto_etherip',
    'proto_fc', 'proto_fire', 'proto_ggp', 'proto_gmtp', 'proto_gre',
    'proto_hmp', 'proto_i-nlsp', 'proto_iatp', 'proto_ib', 'proto_idpr',
    'proto_idpr-cmtp', 'proto_idrp', 'proto_ifmp', 'proto_igmp', 'proto_igp',
    'proto_il', 'proto_ip', 'proto_ipcomp', 'proto_ipcv', 'proto_ipip',
    'proto_iplt', 'proto_ipnip', 'proto_ippc', 'proto_ipv6',
    'proto_ipv6-frag', 'proto_ipv6-no', 'proto_ipv6-opts',
    'proto_ipv6-route', 'proto_ipx-n-ip', 'proto_irtp', 'proto_isis',
    'proto_iso-ip', 'proto_iso-tp4', 'proto_kryptolan', 'proto_l2tp',
    'proto_larp', 'proto_leaf-1', 'proto_leaf-2', 'proto_merit-inp',
    'proto_mfe-nsp', 'proto_mhrp', 'proto_micp', 'proto_mobile', 'proto_mtp',
    'proto_mux', 'proto_narp', 'proto_netblt', 'proto_nsfnet-igp', 'proto_nvp',
    'proto_ospf', 'proto_pgm', 'proto_pim', 'proto_pipe', 'proto_pnni',
    'proto_pri-enc', 'proto_prm', 'proto_ptp', 'proto_pup', 'proto_pvp',
    'proto_qnx', 'proto_rdp', 'proto_rsvp', 'proto_rvd', 'proto_sat-expak',
    'proto_sat-mon', 'proto_sccopmce', 'proto_scps', 'proto_sctp',
    'proto_sdrp', 'proto_secure-vmtp', 'proto_sep', 'proto_skip', 'proto_sm',
    'proto_smp', 'proto_snp', 'proto_sprite-rpc', 'proto_sps', 'proto_srp',
    'proto_st2', 'proto_stp', 'proto_sun-nd', 'proto_swipe', 'proto_tcf',
    'proto_tcp', 'proto_tlsp', 'proto_tp++', 'proto_trunk-1', 'proto_trunk-2',
    'proto_ttp', 'proto_udp', 'proto_unas', 'proto_uti', 'proto_vines',
    'proto_visa', 'proto_vmtp', 'proto_vrrp', 'proto_wb-expak', 'proto_wb-mon',
    'proto_wsn', 'proto_xnet', 'proto_xns-idp', 'proto_xtp', 'proto_zero',
    # service one-hot (13 categories)
    'service_-', 'service_dhcp', 'service_dns', 'service_ftp',
    'service_ftp-data', 'service_http', 'service_irc', 'service_pop3',
    'service_radius', 'service_smtp', 'service_snmp', 'service_ssh',
    'service_ssl',
    # state one-hot (7 categories)
    'state_ACC', 'state_CLO', 'state_CON', 'state_FIN', 'state_INT',
    'state_REQ', 'state_RST',
]


def preprocess(record: dict) -> np.ndarray:
    """
    Transform a raw feature dict into a (1, 183) float32 numpy array.

    Parameters
    ----------
    record : dict
        Must contain 32 numerical keys + 'proto', 'service', 'state'.
        May optionally contain 'src_ip', 'dst_ip' (ignored here).

    Returns
    -------
    np.ndarray of shape (1, 183), dtype float32
    """
    # 1. Build single-row DataFrame from numerical columns only
    num_data = {col: [float(record.get(col, 0))] for col in NUMERICAL_COLS}
    df = pd.DataFrame(num_data)

    # 2. One-hot encode the categorical columns
    for cat_col in CATEGORICAL_COLS:
        cat_value = str(record.get(cat_col, "-")).lower()
        df[cat_col] = cat_value

    df = pd.get_dummies(df, columns=CATEGORICAL_COLS)

    # 3. Reindex to exactly FEATURE_COLUMNS; unseen cats -> 0, extra cols dropped
    df = df.reindex(columns=FEATURE_COLUMNS, fill_value=0)

    # 4. Scale the first 32 numerical columns in-place
    df.iloc[:, :32] = scaler.transform(df.iloc[:, :32])

    # 5. Return float32 numpy array
    return df.values.astype(np.float32)


def decode_label(index: int) -> str:
    """Convert integer class index to class name using the LabelEncoder."""
    return label_encoder.inverse_transform([index])[0]