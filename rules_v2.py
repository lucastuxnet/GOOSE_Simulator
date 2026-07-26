# Regras de detecção geradas pelo LLM (limpas)
# Origem: rules_raw.py
# Data: 15/07/2026 09:54:57
# Para uso no pipeline de detecção GOOSE IEC 61850

def rule_grayhole_low_sqnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole."""
    sqnum = packet.get("SqNum", 0)
    tdiff = packet.get("tDiff", 0)
    return sqnum < 4.9 and tdiff > 1000

def rule_grayhole_low_stnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole."""
    stnum = packet.get("StNum", 0)
    sqnum = packet.get("SqNum", 0)
    return stnum < 173.9 and sqnum < 4.9

def rule_grayhole_high_stdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole."""
    stdiff = packet.get("stDiff", 0)
    sqnum = packet.get("SqNum", 0)
    return stdiff > -32.0 and sqnum < 4.9

def rule_grayhole_low_tdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole."""
    tdiff = packet.get("tDiff", 0)
    timefromlastchange = packet.get("timeFromLastChange", 0)
    return tdiff < -107.5024 and timefromlastchange < 0.557


# === high_StNum ===

def rule_high_StNum_regra1(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum."""
    st_num = packet.get("StNum", 0)
    st_diff = packet.get("stDiff", 0)
    return (st_num > 679.0) and (st_diff > 392.0)

def rule_high_StNum_regra2(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum."""
    sq_diff = packet.get("sqDiff", 0)
    time_from_last_change = packet.get("timeFromLastChange", 0)
    return (sq_diff > 31.0) and (time_from_last_change < 0.0)


# === injection ===

def rule_injection_high_sqnum(packet: dict) -> bool:
    sqnum = packet.get("SqNum", 0)
    stnum = packet.get("StNum", 0)
    return sqnum > 55 and stnum < 35

def rule_injection_low_stnum(packet: dict) -> bool:
    stnum = packet.get("StNum", 0)
    sqdiff = packet.get("sqDiff", 0)
    return stnum < 35 and sqdiff > 31


# === inverse_replay ===

def rule_inverse_replay_low_sqnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de inverse_replay."""
    sqnum = packet.get("SqNum", 0)
    stnum = packet.get("StNum", 0)
    return (sqnum < 1.0) and (stnum < 35.0)

def rule_inverse_replay_high_stdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de inverse_replay."""
    stdiff = packet.get("stDiff", 0)
    timefromlastchange = packet.get("timeFromLastChange", 0)
    return (stdiff > 392.0) and (timefromlastchange > 50.9807)


# === masquerade_fake_fault ===

def rule_masquerade_fake_fault_low_stnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_fault."""
    stnum = packet.get("StNum", 0)
    cbstatus = packet.get("cbStatus", 0)
    return stnum < 173.9 and cbstatus > 0.55

def rule_masquerade_fake_fault_high_tdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_fault."""
    tdiff = packet.get("tDiff", 0)
    timestampdiff = packet.get("timestampDiff", 0)
    return tdiff > 1977.8429 and timestampdiff > 0.1721

def rule_masquerade_fake_fault_high_cbstatus(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_fault."""
    cbstatus = packet.get("cbStatus", 0)
    stdiff = packet.get("stDiff", 0)
    return cbstatus > 0.55 and stdiff > 266.75

def rule_masquerade_fake_fault_low_sqnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_fault."""
    sqnum = packet.get("SqNum", 0)
    timestampdiff = packet.get("timestampDiff", 0)
    return sqnum < 10 and timestampdiff > 0.3


# === masquerade_fake_normal ===

def rule_masquerade_fake_normal_low_sqnum_high_stnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_normal."""
    sqnum = packet.get("SqNum", 0)
    stnum = packet.get("StNum", 0)
    return (sqnum < 1.0) and (stnum > 679.0)

def rule_masquerade_fake_normal_low_timestampdiff_high_stdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_normal."""
    timestampdiff = packet.get("timestampDiff", 0)
    stdiff = packet.get("stDiff", 0)
    return (timestampdiff < 0.0) and (stdiff > 392.0)


# === poisoned_high_rate ===

def rule_poisoned_high_rate_low_sqnum_high_stnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de poisoned_high_rate."""
    sqnum = packet.get("SqNum", 0)
    stnum = packet.get("StNum", 0)
    return (sqnum < 1.0) and (stnum > 679.0)

def rule_poisoned_high_rate_high_cbstatus_high_timestampdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de poisoned_high_rate."""
    cbstatus = packet.get("cbStatus", 0)
    timestampdiff = packet.get("timestampDiff", 0)
    return (cbstatus > 1.0) and (timestampdiff > 0.3765)


# === random_replay ===

def rule_random_replay_high_sqnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de random_replay."""
    sqnum = packet.get("SqNum", 0)
    stnum = packet.get("StNum", 0)
    return sqnum > 55 and stnum < 100

def rule_random_replay_low_stnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de random_replay."""
    stnum = packet.get("StNum", 0)
    stdiff = packet.get("stDiff", 0)
    return stnum < 155 and stdiff < -40000

def rule_random_replay_high_timestamp_diff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de random_replay."""
    timestamp_diff = packet.get("timestampDiff", 0)
    time_from_last_change = packet.get("timeFromLastChange", 0)
    return timestamp_diff > 0.1991 and time_from_last_change > 37.8508

def rule_random_replay_high_sqdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de random_replay."""
    sqdiff = packet.get("sqDiff", 0)
    stdiff = packet.get("stDiff", 0)
    return sqdiff > 30 and stdiff < -50000

