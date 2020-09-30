from make_tables import sdk2pretty
from make_tables import add_footer
from make_tables import rot, bf, head

# "arraycopy",
# "arrayops",
# "baload_bastore",
# "cast_to_short",
# "example_attack",
# "fuzz_verifiers",
# "localvars",
# "nativemethod",
# "referencelocation",
# "stack_underflow",
# "staticfield_ref",
# "swap_x",
# "transaction_confusion",
# }

cards = [
    "A",
    "B",
    "C",
    "C*",
    "D",
    # "E",
    "F",
    "G",
    "H",
    "I",
    "I*",
    "J",
]


attacks = {}
attacks["arraycopy"] = {
    "A": False,
    "B": "-",
    "C": False,
    "C*": False,
    "D": False,
    "E": "-",
    "F": False,
    "G": False,
    "H": False,
    "I": False,
    "I*": False,
    "J": "jc304",
}
attacks["arrayops"] = {
    "A": False,
    "B": "-",
    "C": False,
    "C*": False,
    "D": False,
    "E": "-",
    "F": False,
    "G": False,
    "H": False,
    "I": False,
    "I*": False,
    "J": False,
}

attacks["baload_bastore"] = {
    "A": False,
    "B": False,
    "C": False,
    "C*": False,
    "D": False,
    "E": "-",
    "F": False,
    "G": False,
    "H": False,
    "I": False,
    "I*": False,
    "J": False,
}

attacks["nativemethod"] = {
    "A": False,
    "B": False,
    "C": False,
    "C*": False,
    "D": False,
    "E": "-",
    "F": False,
    "G": False,
    "H": False,
    "I": False,
    "I*": False,
    "J": False,
}

attacks["referencelocation"] = {
    "A": "jc304",
    "B": "-",
    "C": False,
    "C*": False,
    "D": False,
    "E": "-",
    "F": False,
    "G": False,
    "H": False,
    "I": False,
    "I*": False,
    "J": False,
}

attacks["staticfield_ref"] = {
    "A": "jc304",
    "B": "-",
    "C": False,
    "C*": False,
    "D": False,
    "E": "-",
    "F": "jc222",
    "G": False,
    "H": "jc222",
    "I": False,
    "I*": False,
    "J": "jc221",
}

attacks["swap_x"] = {
    "A": False,
    "B": "-",
    "C": False,
    "C*": False,
    "D": False,
    "E": "-",
    "F": "jc222",
    "G": False,
    "H": "jc222",
    "I": False,
    "I*": "jc221",
    "J": "jc221",
}

attacks["transaction_confusion"] = {
    "A": False,
    "B": False,
    "C": False,
    "C*": False,
    "D": False,
    "E": "-",
    "F": False,
    "G": False,
    "H": False,
    "I": False,
    "I*": False,
    "J": "-",
}


if __name__ == "__main__":
    # TODO add SDK explanation to the list of abbreviations
    table = ["\\begin{table}[htb!]"]
    table.append("\t\\footnotesize")
    table.append("\n\t\\centering")

    # names = [stage["name"] for stage in stages]
    # TODO fix the long column names
    names = list(attacks.keys())[::]
    # for stage in stages:
    #     if stage["name"] == "send":
    #         names.append(stage["comment"])
    #     else:
    #         names.append(stage["name"])
    # names = [rot(bf(name)) for name in names]

    names = [head(name) for name in names]
    n_cols = len(names)

    names.insert(0, bf("card"))
    # names.insert(1, bf("SDK"))
    heading = "\t&\t".join(names) + "\\\\"
    table.append("\t\\begin{tabular}{@{}" + "l" + "c" * n_cols + "@{}}")

    table.append("\\toprule")
    table.append(heading)
    table.append("\\midrule")
    # insert values
    for card in cards:
        line = [card]
        for attack, results in attacks.items():
            res = results[card]
            if res:
                if res == "-":
                    line.append("-")
                else:
                    line.append(sdk2pretty[res])
            else:
                line.append("\\failmark")
        table.append("\t&\t".join(line) + "\\\\")

    table = add_footer(
        table,
        caption="Overview of the attacks accross all the different cards.",
        label="tab:results-overview",
    )
    end = "\\end{table}"
    if table[-1] != end:
        table.append(end)

    with open("subtables/results-overview.tex", "w") as f:
        f.write("\n".join(table))
