"""Revisit 2.0 memory gatekeeper (frozen before the first fresh300 model call; designed on s300 clean results only).

Two answer paths run for every new CVE:
  memory path   = OURS (Planner reads H-MEM -> Executor -> Evaluator)
  evidence path = S    (same Nemotron, raw tracker lines, no memory)
The gatekeeper decides, per item, whether to trust the memory path. It never sees the answer. Inputs: the two proposals and
H-MEM features computed by hmem_features.py (current stances after supersession, recall hits).

Rules, in order:
  0. agree            : both paths give the same decision -> that decision.
  1. class_unreliable : memory is not a reliable judge for this class. A WONTFIX proposal from the evidence path means
                        "this specific CVE has no real impact" (unimportant / ignored), a property of the CVE, not of the
                        package. On the development set the memory path overruled such proposals 18 times and was right
                        2 times (evidence path right 16). For the other classes the memory path won or tied when it
                        overruled (URGENT 15 vs 6, NEXT 17 vs 11, NOTAFF 8 vs 6). -> evidence path.
  2. memory_disagrees_with_itself : H-MEM itself supports the evidence path's answer (it is the package's dominant current
                        stance in H-MEM, or the top H-MEM recall hit), yet the memory path chose something else. The memory
                        path is then not following memory; trust the evidence path (dev: 8 vs 3).
  3. trust_memory     : otherwise -> memory path.
"""
CLASS_UNRELIABLE = {'WONTFIX'}   # from the development set table above; fixed


def decide(f, s_pred, o_pred):
    """f: hmem_features item dict. Returns (decision, rule)."""
    if s_pred == o_pred: return o_pred, 'agree'
    if s_pred in CLASS_UNRELIABLE: return s_pred, 'class_unreliable'
    top = f['hits'][0]['v'] if f.get('hits') else None
    if f.get('n') and (f.get('dom') == s_pred or top == s_pred): return s_pred, 'memory_disagrees_with_itself'
    return o_pred, 'trust_memory'
