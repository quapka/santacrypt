import pymongo
import importlib
import argparse
import subprocess
import contextlib
import os
import copy


class MongoConnection(object):
    def __init__(
        self,
        host="localhost",
        port="27017",
        database="javacard-analysis",
        collation="commands",
    ):
        self.host = host
        self.port = port
        self.connection = None
        self.db_name = database
        self.collation_name = collation

    def __enter__(self, *args, **kwargs):
        conn_str = f"mongodb://{self.host}:{self.port}"

        self.connection = pymongo.MongoClient(conn_str)
        self.db = self.connection[self.db_name]
        self.col = self.db.get_collection(
            self.collation_name  # , codec_options=codec_options
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.connection.close()


@contextlib.contextmanager
def cd(new_path):
    old_path = os.getcwd()
    try:
        # no yield for now, as there is no need for additional information
        os.chdir(new_path)
        yield old_path
    finally:
        # the old directory might also be remove, however there isn't
        # good and logical thing to do, so in that case the exception will be
        # thrown
        # FIXME Ceesjan taught to not to use format in logging!!!
        os.chdir(old_path)


atr2name = {
    "3BFC180000813180459067464A01002005000000004E": "A",
    # "3BFC180000813180459067464A01002005000000004E": "Anew",
    "3BFE1800008031FE4553434536302D43443038312D6E46A9": "B",
    "3B7B1800000031C06477E30300839000": "C",
    "3B7B1800000031C06477E30300829000": "C*",
    "3BF81800008031FE450073C8401300900092": "D",
    "3B9F95803FC7A08031E073FA21106300000083F09000BB": "E",
    "3BF81300008131FE454A434F5076323431B7": "F",
    "3B6D000080318065409086015183079000": "G",
    "3BF81800FF8131FE454A434F507632343143": "H",
    "3B7B1800000031C06477E910007F9000": "I",
    "3B7B1800000031C06477E91000019000": "I*",
    "3B9495810146545601C4": "J",
}

sdk2pretty = {
    "jc211": "2.1.1.",
    "jc212": "2.1.2.",
    "jc221": "2.2.1",
    "jc222": "2.2.2",
    "jc303": "3.0.3",
    "jc304": "3.0.4",
    "jc305u1": "3.0.5u1",
    "jc305u2": "3.0.5.u2",
    "jc305u3": "3.0.5u3",
    "jc310b43": "3.1.0b43",
}

attack2name = {
    "arraycopy": "ArrayCopy",
    "arrayops": "ArrayOps",
    "baload_bastore": "BaloadBastore",
    "cast_to_short": "CastToShort",
    "example_attack": "ExampleAttack",
    "fuzz_verifiers": "FuzzVerifiers",
    "localvars": "Localvars",
    "nativemethod": "NativeMethod",
    "referencelocation": "ReferenceLocation",
    "stack_underflow": "StackUnderflow",
    "staticfield_ref": "StaticFieldRef",
    "swap_x": "Swap_x",
    "transaction_confusion": "TransactionConfusion",
}


def add_space(value: str, sep: str = " "):
    chunks = [value[i : i + 2] for i in range(0, len(value), 2)]
    return sep.join(chunks)


def print_attack(data, name):
    result = "%s " % name
    for stage in data["analysis-results"][name]["results"]:
        if stage["skipped"]:
            result += "S"
        elif stage["success"]:
            result += "P"
        else:
            result += "F"
        # except KeyError:
        #     result += "E"
        result += " "
    print(result)


def as_tex_row(name, sdk, stages):
    row = ""
    marks = [name, sdk2pretty[sdk]]
    for stage in stages:
        pass
        if stage["skipped"]:
            marks.append("\\skipmark")
        elif stage["success"]:
            marks.append("\\passmark")
        else:
            marks.append("\\failmark")

    return "\t&\t".join(marks) + "\\\\"


def bf(value):
    return "\\textbf{" + value + "}"


def rot(value):
    return "\\rot{" + value + "}"


def tt(value):
    return "\\texttt{" + value + "}"


def small(value):
    return "{\\small %s }" % value


def head(value):
    return small(tt(rot(bf(value))))


def create_table_header(stages):
    # TODO add SDK explanation to the list of abbreviations
    # table = ["\\begin{table}[htb]"]
    table = []
    table.append("\t\\footnotesize")
    table.append("\t\\centering")

    # names = [stage["name"] for stage in stages]
    names = []
    for stage in stages:
        if stage["name"] == "send":
            names.append(stage["comment"])
        else:
            names.append(stage["name"])
    # names = [rot(bf(name)) for name in names]
    names = [head(name) for name in names]
    n_cols = len(names)
    names.insert(0, bf("card"))
    names.insert(1, bf("SDK"))
    heading = "\t&\t".join(names) + "\\\\"
    table.append("\t\\begin{tabular}{@{}" + "ll" + "c" * n_cols + "@{}}")
    table.append("\\toprule")
    table.append(heading)
    table.append("\\midrule")
    return table


def add_footer(table, caption=None, label=""):
    table.append("\\bottomrule")
    table.append("\\end{tabular}")
    if caption is not None:
        table.append("\\caption{" + caption + "}")
    if label:
        table.append("\\label{" + label + "}")
    # table.append("\\end{table}")
    return table


def find_best_attack(name):
    """
    For each card finds the run with the best attack for `name`
    """
    sdks = "jc211,jc,212,jc221,jc222,jc303,jc304,jc305u1,jc305u2,jc305u3,jc310b43".split(
        ","
    )
    atrs = list(atr2name.keys())
    atrs = [add_space(x) for x in atrs]

    best = []
    with MongoConnection() as con:
        for atr in atrs:
            results = []
            for sdk in sdks:
                attack = "-".join([name, sdk])
                field = "analysis-results.%s" % attack
                filtr = {
                    field: {"$exists": True},
                    "card.atr": atr,
                }
                runs = list(con.col.find(filtr, projection=[field]))
                for run in runs:
                    score = score_attack(run["analysis-results"][attack]["results"])
                    results.append((atr, score, run, sdk))
            # TODO just save the stages mg..
            results.sort(key=lambda x: x[3], reverse=True)
            results.sort(key=lambda x: x[1], reverse=True)
            # if atr2name[atr.replace(" ", "")] == "A":
            #     import pudb

            #     pudb.set_trace()
            if results:
                best.append(results[0])

    return best


def score_attack(stages):
    score = 0
    for stage in stages:
        try:
            if stage["success"]:
                score += 1
        except KeyError:
            break
    return score


def main(attack_name):
    sdks = "jc221,jc222,jc303,jc304,jc305u1,jc305u2,jc305u3".split(",")
    # sdks = "jc221".split(",")

    attack_name = "baload_bastore"
    with MongoConnection() as con:
        atrs = con.col.find(
            {"card.atr": {"$exists": True}}, projection={"card.atr"}
        ).distinct("card.atr")

        atrs = [a for a in atrs if isinstance(a, str)]
        header_run = con.col.find_one(
            {"analysis-results.baload_bastore-jc222": {"$exists": True}},
            # projection=["analysis-results." + attack_name],
        )

        for sdk in sdks:
            table = create_table_header(
                header_run["analysis-results"]["baload_bastore-jc222"]["results"]
            )
            for atr in atrs:
                # print(atr)
                attack = "%s-%s" % (attack_name, sdk)
                project = "analysis-results.%s" % attack
                runs = con.col.find(
                    {"card.atr": atr, project: {"$exists": True}}, projection=[project]
                )

                for run in runs:
                    # print(as_tex_row(d, attack))
                    stages = run["analysis-results"][attack]["results"]
                    name = atr2name[atr.replace(" ", "")]
                    table.append(as_tex_row(name, sdk, stages))

            table = add_footer(table, caption=sdk)
            print("\n".join(table))


def save_objs_attack(stages, objs, attack):
    # tmp = attack + "-" + objs[0][3]
    # with MongoConnection() as con:
    # table = create_table_header(objs[0][2]["analysis-results"][tmp]["results"])
    table = create_table_header(stages)
    project = "analysis-results.%s" % attack
    # runs = con.col.find(
    #     {"card.atr": atr, project: {"$exists": True}}, projection=[project]
    # )

    i = 0
    for atr, score, obj, sdk in objs:
        print(i)
        i += 1
        # print(as_tex_row(d, attack))
        name = attack + "-" + sdk
        stages = obj["analysis-results"][name]["results"]
        card_name = atr2name[atr.replace(" ", "")]  # + "-" + sdk
        table.append(as_tex_row(card_name, sdk, stages))

    label = "tab:best-%s" % attack
    table = add_footer(
        table,
        # caption="The best results for %s attack across all the cards and SDKs."
        caption="\\texttt{%s}" % attack,
        label=label,
    )
    tex_table = "\n".join(table)

    filename = "subtables/best-%s.tex" % attack
    filename = filename.replace("_", "-")
    with open(filename, "w") as f:
        f.write(tex_table)


def load_attack_stages(name):
    # module_path = f"/home/qup/projects/fi/thesis/javus/data/attacks/{name}/{name}.py"
    # cmd = ["ln", "--symbolic", module_path]
    # subprocess.run(cmd)
    # try:
    module = f"javus.data.attacks.{name}.{name}"
    Scenario = getattr(importlib.import_module(module), "Scenario")
    # except (ModuleNotFoundError, AttributeError):
    #     print("Error: cannot load %s" % name)
    #     return
    stages = copy.deepcopy(Scenario.STAGES)
    result = copy.deepcopy(stages)
    for stage in stages:
        if stage["name"] == "install":
            result.append({"name": "uninstall"})

    return result


def create_best_attack_table(attack):
    bests = find_best_attack(name=attack)
    stages = load_attack_stages(attack)
    save_objs_attack(stages, bests, attack)


def create_attack_atr_table(attack, atr):
    sdks = "jc211,jc212,jc221,jc222,jc303,jc304,jc305u1,jc305u2,jc305u3,jc310b43".split(
        ","
    )
    sdks.sort()

    stages = load_attack_stages(attack)
    with MongoConnection() as con:
        table = create_table_header(stages)
        for sdk in sdks:
            attack_name = "%s-%s" % (attack, sdk)
            field = "analysis-results.%s" % (attack_name)
            filtr = {field: {"$exists": True}, "card.atr": add_space(atr)}
            data = con.col.find(filtr)
            data = list(data)
            data.sort(
                key=lambda x: score_attack(
                    x["analysis-results"][attack_name]["results"]
                ),
                reverse=True,
            )
            # if atr2name[atr.replace(" ", "")] == "J":
            #     import pudb

            #     pudb.set_trace()

            for d in data[:1]:
                # name = "-".join([atr2name[atr], sdk])
                card = atr2name[atr]
                table.append(
                    as_tex_row(card, sdk, d["analysis-results"][attack_name]["results"])
                )
        table = add_footer(table, caption=attack + " for " + atr2name[atr])
    card = atr2name[atr]
    attack = attack.replace("_", "-")
    with open("subtables/" + attack + card + ".tex", "w") as f:
        f.write("\n".join(table))


if __name__ == "__main__":
    # main()
    attacks = [
        "arraycopy",
        "arrayops",
        "baload_bastore",
        "cast_to_short",
        "example_attack",
        "fuzz_verifiers",
        "localvars",
        "nativemethod",
        "referencelocation",
        "stack_underflow",
        "staticfield_ref",
        "swap_x",
        "transaction_confusion",
    ]
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--attack")
    args = parser.parse_args()

    print("building 'best' results.")
    if args.attack is not None:
        print("  %s" % args.attack)
        create_best_attack_table(args.attack)
    else:
        for attack in attacks:
            print("  %s" % attack)
            create_best_attack_table(attack)

    print("building 'all' results.")
    for attack in attacks:
        print("  %s" % attack)
        for atr in atr2name.keys():
            print("    %s" % atr2name[atr])
            create_attack_atr_table(attack, atr)
