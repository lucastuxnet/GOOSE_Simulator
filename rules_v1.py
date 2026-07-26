# Regras de detecção geradas pelo LLM (limpas)
# Origem: rules_raw.py
# Data: 13/07/2026 15:20:27
# Para uso no pipeline de detecção GOOSE IEC 61850

def rule_grayhole_sq_tdiff(packet: dict) -> bool:
    """Detect grayhole: low SqNum combined with high tDiff."""
    sq_num = packet.get("SqNum", 0)
    t_diff = packet.get("tDiff", 0)
    return (sq_num < 5) and (t_diff > 1500)

def rule_grayhole_sq_stdiff(packet: dict) -> bool:
    """Detect grayhole: low SqNum combined with large positive stDiff."""
    sq_num = packet.get("SqNum", 0)
    st_diff = packet.get("stDiff", 0)
    return (sq_num < 5) and (st_diff > 500)

def rule_grayhole_sq_timechange(packet: dict) -> bool:
    """Detect grayhole: very low SqNum with long time since last change."""
    sq_num = packet.get("SqNum", 0)
    time_from_last_change = packet.get("timeFromLastChange", 0)
    return (sq_num < 3) and (time_from_last_change > 100)


# === high_StNum ===

def rule_high_StNum_stnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum baseado em StNum e stDiff."""
    stnum = packet.get("StNum", 0)
    stdiff = packet.get("stDiff", 0)
    return (stnum > 1000) and (stdiff > 500)

def rule_high_StNum_timing(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum baseado em tDiff e timestampDiff."""
    tdiff = packet.get("tDiff", 0)
    timestampdiff = packet.get("timestampDiff", 0)
    return (tdiff > 2000) and (timestampdiff > 0.4)


# === injection ===

def rule_injection_seq_state(packet: dict) -> bool:
    """Detect injection by abnormal sequence and state numbers."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num > 80) and (st_num < 20)

def rule_injection_timing_status(packet: dict) -> bool:
    """Detect injection by implausible timestamp delta and invalid status."""
    t_diff = packet.get("tDiff", 0)
    cb_status = packet.get("cbStatus", 0)
    return (t_diff < -1500) and (cb_status > 1)


# === inverse_replay ===

def rule_inverse_replay_seq_state(packet: dict) -> bool:
    """Detect inverse replay by extremely low sequence and state numbers."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num == 0) and (st_num < 30)

def rule_inverse_replay_stdiff_time(packet: dict) -> bool:
    """Detect inverse replay by large state-number jump and long idle interval."""
    st_diff = packet.get("stDiff", 0)
    time_last_change = packet.get("timeFromLastChange", 0)
    return (st_diff > 500) and (time_last_change > 120)


# === masquerade_fake_fault ===

def rule_masquerade_fake_fault_tdiff_ts(packet: dict) -> bool:
    """Detects masquerade_fake_fault when inter-message gap and timestamp drift are high."""
    tDiff = packet.get("tDiff", 0)
    timestampDiff = packet.get("timestampDiff", 0)
    return (tDiff > 1000) and (timestampDiff > 0.2)

def rule_masquerade_fake_fault_tdiff_stdiff(packet: dict) -> bool:
    """Detects masquerade_fake_fault when inter-message gap is high and state-difference spikes."""
    tDiff = packet.get("tDiff", 0)
    stDiff = packet.get("stDiff", 0)
    return (tDiff > 1000) and (stDiff > 300)

def rule_masquerade_fake_fault_sqnum_ts(packet: dict) -> bool:
    """Detects masquerade_fake_fault when sequence number is unusually low and timestamp drift is large."""
    sqNum = packet.get("SqNum", 0)
    timestampDiff = packet.get("timestampDiff", 0)
    return (sqNum < 10) and (timestampDiff > 0.3)

def rule_masquerade_fake_fault_stnum_cbstatus(packet: dict) -> bool:
    """Detects masquerade_fake_fault when state number is low and breaker status is forced closed."""
    StNum = packet.get("StNum", 0)
    cbStatus = packet.get("cbStatus", 0)
    return (StNum < 100) and (cbStatus == 1)


# === masquerade_fake_normal ===

def rule_masquerade_fake_normal_low_seq_high_state(packet: dict) -> bool:
    """Retorna True se o pacote apresentar sequência baixa e número de estado excessivo."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num < 1.0) and (st_num > 680)

def rule_masquerade_fake_normal_state_jump_delay(packet: dict) -> bool:
    """Retorna True se o pacote apresentar salto positivo grande no número de estado e atraso fora do normal."""
    st_diff = packet.get("stDiff", 0)
    delay = packet.get("delay", 0)
    return (st_diff > 400) and (delay > 0.001)


# === poisoned_high_rate ===

def rule_poisoned_high_rate_seq_state(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de poisoned_high_rate (sequência e estado)."""
    stnum = packet.get("StNum", 0)
    sqdiff = packet.get("sqDiff", 0)
    return (stnum > 700) and (sqdiff < -63)

def rule_poisoned_high_rate_timing(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de poisoned_high_rate (timing anômalo)."""
    tdiff = packet.get("tDiff", 0)
    time_from_last_change = packet.get("timeFromLastChange", 0)
    delay = packet.get("delay", 0)
    return (tdiff < -120) and (time_from_last_change > 100) and (delay > 0.001)


# === random_replay ===

def rule_random_replay_sqnum_stnum(packet: dict) -> bool:
    """Detect random replay by high SqNum together with low StNum."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num > 55) and (st_num < 100)

def rule_random_replay_stdiff_sqdiff(packet: dict) -> bool:
    """Detect random replay using extreme negative stDiff and large forward sqDiff."""
    st_diff = packet.get("stDiff", 0)
    sq_diff = packet.get("sqDiff", 0)
    return (st_diff < -40000) and (sq_diff > 30)

def rule_random_replay_timestamp_timeidle(packet: dict) -> bool:
    """Detect random replay by timestamp drift and prolonged idle before change."""
    ts_diff = packet.get("timestampDiff", 0)
    idle_time = packet.get("timeFromLastChange", 0)
    return (ts_diff > 0.35) and (idle_time > 45)

def rule_random_replay_sqnum_timestamp(packet: dict) -> bool:
    """Detect random replay by moderate SqNum overflow combined with timestamp drift."""
    sq_num = packet.get("SqNum", 0)
    ts_diff = packet.get("timestampDiff", 0)
    return (sq_num > 37) and (ts_diff > 0.1721)

