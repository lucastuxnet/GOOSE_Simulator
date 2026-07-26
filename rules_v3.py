# Regras de detecção geradas pelo LLM (limpas)
# Origem: rules_raw.py
# Data: 15/07/2026 10:54:49
# Para uso no pipeline de detecção GOOSE IEC 61850

def rule_injection_sq_st(packet: dict) -> bool:
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num > 36.15) and (st_num < 173.9)

def rule_injection_sq_st(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de injection."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num > 36.15) and (st_num < 173.9)

def rule_poisoned_high_rate_1(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de poisoned_high_rate."""
    st_num = packet.get("StNum", 0)
    time_from_last_change = packet.get("timeFromLastChange", 0)
    return (st_num > 679.0) and (time_from_last_change > 50.9807)

def rule_poisoned_high_rate_2(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de poisoned_high_rate."""
    t_diff = packet.get("tDiff", 0)
    timestamp_diff = packet.get("timestampDiff", 0)
    return (t_diff < -120.4257) and (timestamp_diff > 0.3765)

