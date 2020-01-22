#!/usr/bin/python3

# crackme page:  https://crackmes.one/crackme/5d7c66d833c5d46f00e2c45b
# download link: https://crackmes.one/static/crackme/5d7c66d833c5d46f00e2c45b.zip
# zip archive password: crackmes.one

import angr
import claripy
import subprocess
from datetime import datetime


def skip_banner(state):
    pass


def emulate():

    proj = angr.Project("keygenme_patched",
                        main_opts = {"base_addr": 0},
                        auto_load_libs = False)

    # skip code
    proj.hook(0x00001166, skip_banner, length = 0x00001177 - 0x00001166)

    # create symbolic variables to solve for
    username = claripy.BVS("username", 10 * 8)

    password_bytes = [claripy.BVS("byte_%d" % i, 8) for i in range(15)]
    password_bytes_ast = claripy.Concat(*password_bytes)
    password_file = angr.storage.file.SimFile("pass.txt", content = password_bytes_ast)

    state = proj.factory.entry_state(args = [ "keygenme_patched", username, "pass.txt"])
    state.fs.insert("pass.txt", password_file)

    # add some constraints
    for byte in password_bytes:
        state.solver.add(byte >= 0x41)
        state.solver.add(byte <= 0x5a)

    # explore
    sim_mgr = proj.factory.simulation_manager(state)

    print("[ %s ] Exploration started..." % datetime.now().time())
    sim_mgr.explore(find = 0x00001560,      # good password
                    avoid = [ 0x000012c2,   # in main, argc != 3, exit
                              0x000012ff,   # in main, bad username
                              0x00001b8a,   # in 0x1a00, can't open file
                              0x00001b50,   # in 0x1a00, empty file
                              0x00001b10,   # in 0x1a00, wrong password length or invalid char
                              0x00001aef,   # in 0x1a00, bad password
                              0x00001ba8,   # in 0x1a00, __stack_check_fail
                              0x00001e45,   # in 0x1bb0, avoid to reduce complexity
                              0x00001c85 ]) # in 0x1bb0, bad password
    print("[ %s ] Finished..." % datetime.now().time())

    # compute 1 valid username
    # for that username compute 1 valid password
    if len(sim_mgr.found) > 0:
        print("[ %s ] Computing valid username... " % datetime.now().time())
        found = sim_mgr.found[0]
        valid_username = found.solver.eval(username, cast_to = bytes)                           # compute username
        print("[ %s ] Username: %s" % (datetime.now().time(), valid_username.decode("ASCII")))
        print("[ %s ] Computing valid password... " % datetime.now().time())
        valid_password = found.solver.eval(password_bytes_ast, cast_to = bytes)                 # compute password
        print("[ %s ] Password: %s" % (datetime.now().time(), valid_password.decode("ASCII")))
        print("[ %s ] Checking..." % datetime.now().time())

        with open("key.txt", "w") as f:
            f.write(valid_password.decode("ASCII"))                                             # write generated password to input file

        _ = subprocess.run(["./keygenme_patched", valid_username, "key.txt"], stdout = subprocess.PIPE) # execute crackme, discard output

        with open("key.txt", "r") as f:                                                         # check message written to file
            message = f.read()
            print("[ %s ] %s:  %s" % (datetime.now().time(), valid_password.decode("ASCII"), repr(message)))
    else:
        print("No solution found")



if __name__ == "__main__":
    emulate()