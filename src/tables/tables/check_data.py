import argparse
from make_tables import MongoConnection

attacks = [
    "arraycopy",
    "arrayops",
    "baload_bastore",
    "cast_to_short",
    "fuzz_verifiers",
    "localvars",
    "nativemethod",
    "referencelocation",
    "stack_underflow",
    "staticfield_ref",
    "swap_x",
    "transaction_confusion",
]
sdks = "jc211,jc310b43,jc221,jc222,jc303,jc304,jc305u1,jc305u2,jc305u3".split(",")


def find_culprit(field="stdout"):
    with MongoConnection() as con:
        for attack in attacks:
            for sdk in sdks:
                field = "analysis-results.%s-%s" % (attack, sdk)
                data = con.col.find({field: {"$exists": True}})

                for d in data:
                    for stage in d["analysis-results"]["-".join([attack, sdk])][
                        "results"
                    ]:
                        if not stage["skipped"]:
                            try:
                                stage["args"]
                            except KeyError:
                                print(d["_id"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--field", default="stdout")
    args = parser.parse_args()

    field = args.field
    find_culprit(field=field)
