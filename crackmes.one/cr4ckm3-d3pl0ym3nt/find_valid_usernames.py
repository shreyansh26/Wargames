#!/usr/bin/python3

import angr
import claripy
from datetime import datetime


# called in the hook to skip instructions
def skip_banner(state):
    pass


def find_valid_usernames():
    # since the crackme binary is a Position Independent Executable, setting the base address to 0
    # saves us the trouble of having to calculate offsets of any kind
    #
    proj = angr.Project("keygenme_patched", main_opts = {"base_addr": 0}, auto_load_libs = False)


    # skip code that has no bearing on the rest of the program
    proj.hook(0x00001166, skip_banner, length = 0x00001177 - 0x00001166)


    # symbolic variable (bitvector) compute values for username
    # 10 characters in length * 8 bits per byte
    #
    # https://docs.angr.io/core-concepts/solver
    # https://github.com/angr/angr-doc/blob/master/examples/whitehat_crypto400/solve.py
    username = claripy.BVS("username", 10 * 8)


    # the arg3 string is just a placeholder here, since exploration ends before the code 
    # opening the password file is reached
    # 
    # the username is checked in the main() function, so the simulation manager does not
    # have to explore very deep into the program. The target address is located in main(),
    # after the checks of the bytes the username is composed of
    #
    state = proj.factory.entry_state(args = ["keygenme_patched", username, "arg3"])
    sim_mgr = proj.factory.simulation_manager(state)

    print("[ %s ] Exploration started..." % datetime.now().time())

    sim_mgr.explore(find = 0x00001264, avoid=[0x000012c2, 0x000012ff])

    print("[ %s ] Finished..." % datetime.now().time())


    # when a path to the target address is found, compute usernames
    # using the constraint solver, then write them to a file
    if len(sim_mgr.found) > 0:
        print("[ %s ] Computing valid usernames... " % datetime.now().time())
        found = sim_mgr.found[0]
        valid_usernames = found.solver.eval_upto(username, 100, cast_to = bytes)  #     <---------
        print("[ %s ] Complete. Writing to file..." % datetime.now().time())
        with open("100_usernames.txt", "w") as f:
            for name in valid_usernames:
                print(name.decode("ASCII"))
                f.write(name.decode("ASCII") + "\n")
    else:
        print("No valid usernames found.") # should never happen


if __name__ == "__main__":
    find_valid_usernames()