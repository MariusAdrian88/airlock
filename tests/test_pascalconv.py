"""Pure parts of the 32-bit Pascal register prototypes (``pascalconv``)."""
from airlock.worker.ghidra_ops import pascalconv as P

F = frozenset


def node(rd=(), wr=(), succ=()):
    return (F(rd), F(wr), tuple(succ))


def test_live_regs_reads_before_writes():
    # mov [ebp-4], eax ; mov ecx, edx ; ret      -> EAX and EDX are arguments, ECX is written first
    nodes = {0: node(("EAX",), (), (1,)), 1: node(("EDX",), ("ECX",), (2,)), 2: node()}
    assert P.live_regs(nodes, 0) == 2
    nodes = {0: node((), ("EAX",), (1,)), 1: node(("EAX",), (), ())}
    assert P.live_regs(nodes, 0) == 0            # EAX is written before the read


def test_live_regs_follows_branches_and_calls():
    # test eax,eax ; jz 3 ; (fallthrough) ret ; 3: read ecx
    nodes = {0: node(("EAX",), (), (1, 3)), 1: node(), 3: node(("ECX",), (), ())}
    assert P.live_regs(nodes, 0) == 3
    # a call that takes two registers reads EAX and EDX and writes all three; ECX after it is not an argument
    nodes = {0: node(("EAX", "EDX"), ("EAX", "EDX", "ECX"), (1,)), 1: node(("ECX",), (), ())}
    assert P.live_regs(nodes, 0) == 2
    # read and write in one instruction (add eax, 1) still reads
    nodes = {0: node(("EAX",), ("EAX",), ())}
    assert P.live_regs(nodes, 0) == 1


def test_live_regs_loop():
    nodes = {0: node((), (), (1,)), 1: node(("EDX",), (), (2,)), 2: node((), (), (1, 3)), 3: node()}
    assert P.live_regs(nodes, 0) == 2


def test_site_reg_count():
    both = [(F(), F({"EAX"})), (F(), F({"EDX"}))]            # nearest first
    assert P.site_reg_count([both, both]) == 2
    assert P.site_reg_count([both, [(F(), F({"EAX"}))]]) == 1      # every caller must load it
    # mov eax, x ; push eax ; call    -> the load feeds a stack argument
    pushed = [(F({"EAX"}), F()), (F(), F({"EAX"}))]
    assert P.site_reg_count([pushed]) == 0
    assert P.site_reg_count([]) == 0


def test_stack_layout_is_pascal_order():
    # TBase.Num(Self, X, Y, Z, W): Z and W on the stack, W at offset 4 (last pushed), Z at 8
    assert P.stack_layout(2, []) == [(8, 4), (4, 4)]
    assert P.stack_layout(0, []) == []
    # Ghidra found only the nearer slot: the gap is filled
    assert P.stack_layout(3, [(4, 4)]) == [(12, 4), (8, 4), (4, 4)]
    # an 8-byte argument covers two slots and keeps its size
    assert P.stack_layout(3, [(8, 8)]) == [(8, 8), (4, 4)]
    # a parameter beyond what the function pops is ignored
    assert P.stack_layout(1, [(8, 4)]) == [(4, 4)]


def test_wanted_layout():
    assert P.wanted_layout(3, 2, []) == (("EAX", "EDX", "ECX"), [(8, 4), (4, 4)])
    assert P.wanted_layout(1, 0, []) == (("EAX",), [])
