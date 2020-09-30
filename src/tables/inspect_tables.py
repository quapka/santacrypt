import argparse
from make_tables import MongoConnection, add_space

atr2name = {
    "3BFC180000813180459067464A01002005000000004E": "A",
    "3BFC180000813180459067464A01002005000000004E": "Anew",
    "3BFE1800008031FE4553434536302D43443038312D6E46A9": "B",
    "3B7B1800000031C06477E30300839000": "C",
    "3B7B1800000031C06477E30300829000": "Cnew",
    "3BF81800008031FE450073C8401300900092": "D",
    "3B9F95803FC7A08031E073FA21106300000083F09000BB": "E",
    "3BF81300008131FE454A434F5076323431B7": "F",
    "3B6D000080318065409086015183079000": "G",
    "3BF81800FF8131FE454A434F507632343143": "H",
    "3B7B1800000031C06477E910007F9000": "I",
    "3B7B1800000031C06477E91000019000": "Inew",
    "3B9495810146545601C4": "J",
}

JC_FRAMEWORK_ISO7816 = {
    "6999": {"note": "Applet selection failed", "const": "SW_APPLET_SELECT_FAILED",},
    "6100": {"note": "Response bytes remaining", "const": "SW_BYTES_REMAINING_00",},
    "6E00": {"note": "CLA value not supported", "const": "SW_CLA_NOT_SUPPORTED",},
    "6884": {
        "note": "Command chaining not supported",
        "const": "SW_COMMAND_CHAINING_NOT_SUPPORTED",
    },
    "6986": {
        "note": "Command not allowed (no current EF)",
        "const": "SW_COMMAND_NOT_ALLOWED",
    },
    "6985": {
        "note": "Conditions of use not satisfied",
        "const": "SW_CONDITIONS_NOT_SATISFIED",
    },
    "6C00": {"note": "Correct Expected Length (Le)", "const": "SW_CORRECT_LENGTH_00",},
    "6984": {"note": "Data invalid", "const": "SW_DATA_INVALID",},
    "6A84": {"note": "Not enough memory space in the file", "const": "SW_FILE_FULL",},
    "6983": {"note": "File invalid", "const": "SW_FILE_INVALID",},
    "6A82": {"note": "File not found", "const": "SW_FILE_NOT_FOUND",},
    "6A81": {"note": "Function not supported", "const": "SW_FUNC_NOT_SUPPORTED",},
    "6A86": {"note": "Incorrect parameters (P1,P2)", "const": "SW_INCORRECT_P1P2",},
    "6D00": {"note": "INS value not supported", "const": "SW_INS_NOT_SUPPORTED",},
    "6883": {
        "note": "Last command in chain expected",
        "const": "SW_LAST_COMMAND_EXPECTED",
    },
    "6881": {
        "note": "Card does not support the operation on the specified logical channel",
        "const": "SW_LOGICAL_CHANNEL_NOT_SUPPORTED",
    },
    "9000": {"note": "No Error", "const": "SW_NO_ERROR",},
    "6A83": {"note": "Record not found", "const": "SW_RECORD_NOT_FOUND",},
    "6882": {
        "note": "Card does not support secure messaging",
        "const": "SW_SECURE_MESSAGING_NOT_SUPPORTED",
    },
    "6982": {
        "note": "Security condition not satisfied",
        "const": "SW_SECURITY_STATUS_NOT_SATISFIED",
    },
    "6F00": {"note": "No precise diagnosis", "const": "SW_UNKNOWN",},
    "6200": {
        "note": "Warning, card state unchanged",
        "const": "SW_WARNING_STATE_UNCHANGED",
    },
    "6A80": {"note": "Wrong data", "const": "SW_WRONG_DATA",},
    "6700": {"note": "Wrong length", "const": "SW_WRONG_LENGTH",},
    "6B00": {"note": "Incorrect parameters (P1,P2)", "const": "SW_WRONG_P1P2",},
}


name2atr = {}
for key, value in atr2name.items():
    name2atr[value] = key


def clean_payload(payload):
    return bytes([int(x, 16) for x in payload.split()]).hex().upper()


def inspect_card(card, attack):
    Anew = name2atr["Anew"]
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--attack", default="arrayops")
    parser.add_argument("-c", "--card", default="Anew")
    parser.add_argument("-s", "--sdk")
    args = parser.parse_args()
    attack = args.attack
    card = add_space(name2atr[args.card])

    sdks = [
        "jc211",
        "jc212",
        "jc221",
        "jc222",
        "jc303",
        "jc304",
        "jc305u1",
        "jc305u2",
        "jc305u3",
        "jc310b43",
    ]
    # sdks = ["jc221"]
    if args.sdk is not None:
        sdks = args.sdk.split(",")
    with MongoConnection() as con:
        print(attack)
        for sdk in sdks:
            print(sdk)
            attack_name = "%s-%s" % (attack, sdk)
            field = "analysis-results.%s" % attack_name
            filtr = {"card.atr": card, field: {"$exists": True}}
            data = con.col.find(filtr)
            for run in data:
                print(run["_id"])
                stages = run["analysis-results"][attack_name]["results"]
                for stage in stages:
                    print("  %s" % stage["name"])
                    try:
                        stage["success"]
                    except KeyError:
                        continue
                    if not stage["success"]:
                        if stage["name"] != "send":
                            try:
                                last_err = "\n    ".join(
                                    stage["stderr"].split("\n")[-2:]
                                )
                                print("    %s" % last_err)
                            except KeyError:
                                pass
                        else:
                            try:
                                pay = clean_payload(stage["payload"])
                                print("    %s >>>" % pay)
                                line = "    <<< "
                                resp = stage["communication"][pay]["payload"]
                                status = stage["communication"][pay]["status"].upper()
                                line += "%s : %s" % (resp, status)
                                try:
                                    line += " " + JC_FRAMEWORK_ISO7816[status]["note"]
                                    line += " " + JC_FRAMEWORK_ISO7816[status]["const"]
                                except KeyError:
                                    pass
                                # line = "    %s: %s" % (pay, stage["communication"][pay])
                                print(line)
                            except KeyError:
                                pass
