from vlnr.vuln_models import Slice

def score_slice(s: Slice) -> float:
    """
    Calculates a risk score for a slice.
    """
    base = 0.5
    if "Command Injection" in s.category:
        base = 0.8
    elif "Deserialization" in s.category:
        base = 0.6
    
    score = base
    
    if s.static_class == "obvious_vuln":
        score += 0.1
    
    # Check if from sys.argv
    if any("sys.argv" in t for t in s.source_types):
        score += 0.1
        
    # Subtract if shell=False (if we can infer it, for now we set it in static_class)
    if s.static_class == "suspicious":
        score -= 0.1
        
    return min(1.0, max(0.0, score))
