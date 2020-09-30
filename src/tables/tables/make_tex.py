from make_tables import atr2name

# atr2name = {
#     "3BFC180000813180459067464A01002005000000004E": "A",
#     "3BFC180000813180459067464A01002005000000004E": "Anew",
#     "3BFE1800008031FE4553434536302D43443038312D6E46A9": "B",
#     "3B7B1800000031C06477E30300839000": "C",
#     "3B7B1800000031C06477E30300829000": "Cnew",
#     "3BF81800008031FE450073C8401300900092": "D",
#     "3B9F95803FC7A08031E073FA21106300000083F09000BB": "E",
#     "3BF81300008131FE454A434F5076323431B7": "F",
#     "3B6D000080318065409086015183079000": "G",
#     "3BF81800FF8131FE454A434F507632343143": "H",
#     "3B7B1800000031C06477E910007F9000": "I",
#     "3B7B1800000031C06477E91000019000": "Inew",
#     "3B9495810146545601C4": "J",
# }

attacks = [
    "arraycopy",
    "arrayops",
    "baload_bastore",
    # "cast_to_short",
    # "example_attack",
    # "fuzz_verifiers",
    # "localvars",
    "nativemethod",
    "referencelocation",
    "stack_underflow",
    "staticfield_ref",
    "swap_x",
    "transaction_confusion",
]


def imp(value):
    imp = "    \\import{./}{subtables/%s}" % value
    return imp


lines = []
lines.append("\\section{Overview}")
lines.append(imp("results-overview.tex"))
for attack in attacks:
    attack = attack.replace("_", "-")
    lines.append("\\section{%s}" % attack)
    best = "best-%s.tex" % attack
    lines.append(imp(best))

    for atr, name in atr2name.items():
        filename = "%s%s.tex" % (attack, name)
        lines.append(imp(filename))
    lines.append("\\newpage")


with open("sections.tex", "w") as f:
    f.write("\n".join(lines))
