#!/usr/bin/python3

import angr
import claripy
import subprocess
from datetime import datetime


# argument to hook
def skip_banner(state):
    pass


# since the crackme binary is a Position Independent Executable, setting the base address to 0
# saves us the trouble of having to calculate offsets of any kind
#
def find_valid_passwords():

    proj = angr.Project("keygenme_patched",
                        main_opts = {"base_addr": 0},
                        auto_load_libs = False)

    # skip meaningless code
    proj.hook(0x00001166, skip_banner, length = 0x00001177 - 0x00001166)

    # generate valid passwords for a given known good username
    #username = "6WhOlwIq7K"
    #username = "24T5JFN9fU"
    username = "Z36HiLfBA3"

    # figuring out how to do this was the most difficult aspect of solving the challenge
    #
    # - create a symbolic variable representing the password, then create a SimFile containing this variable
    # - load and read this SimFile during emulation instead of a real file
    #
    # A password length of 4 is quite short and up to 49 characters is acceptable; however, the longer the AST representing the password,
    # the greater the RAM consumed by the solver when computing passwords
    #
    # the following examples were helpful for this task:
    #
    # https://docs.angr.io/advanced-topics/file_system  -  creating the symbolic variable representing the password
    # https://gist.github.com/inaz2/c812671841f97804c24ba6650b1b2500  -  handling command line arguments
    # https://github.com/angr/angr-doc/blob/master/examples/asisctffinals2015_license/solve.py  -  creating and loading the SimFile
    #
    password_bytes = [claripy.BVS("byte_%d" % i, 8) for i in range(8)]
    password_bytes_ast = claripy.Concat(*password_bytes)
    password_file = angr.storage.file.SimFile("pass.txt", content = password_bytes_ast)

    state = proj.factory.entry_state(args = [ "keygenme_patched", username, "pass.txt"])
    state.fs.insert("pass.txt", password_file)

    # constraints restrict possible characters to range A - Z. Done to reduce complexity
    # https://docs.angr.io/core-concepts/solver
    #
    for byte in password_bytes:
        state.solver.add(byte >= 0x41)
        state.solver.add(byte <= 0x5a)


    # the goal is to find a path to the function that writes the "good password" message
    # and avoid all other possible paths
    #
    # https://docs.angr.io/core-concepts/pathgroups
    #
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

    # if path to 0x00001560 is found, use solver to generate valid passwords
    # https://docs.angr.io/core-concepts/solver
    #
    if len(sim_mgr.found) > 0:
        print("[ %s ] Computing valid passwords... " % datetime.now().time())
        found = sim_mgr.found[0]
        passwords = found.solver.eval_upto(password_bytes_ast, 10, cast_to = bytes)

        # verify that the generated passwords are correct.
        #
        # https://github.com/angr/angr-doc/blob/764f9b37003052b449d255a6a880ae8111ebcd06/examples/whitehat_crypto400/solve.py#L87
        # was helpful for this
        #
        valid_passwords = []
        print("[ %s ] Finished. Checking passwords for username %s:" % (datetime.now().time(), username))
        for password in passwords:
            with open("key.txt", "w") as f: f.write(password.decode("ASCII"))                 # write generated password to input file
            _ = subprocess.run(["./keygenme_patched", username, "key.txt"], stdout = subprocess.PIPE) # execute crackme, discard output
            with open("key.txt", "r") as f:                                                   # check message written to file
                message = f.read()
                print("[ + ] %s:  %s" % (password.decode("ASCII"), repr(message)))
                if 'G00d' in message:
                    valid_passwords.append(password)

        # if valid password found, write username and password(s) to file
        if len(valid_passwords) > 0:
            with open("valid_passwords.txt", "a") as f:
                f.write("Username: %s\n" % username)
                for password in valid_passwords:
                    f.write(password.decode("ASCII") + "\n")
        print("[ %s ] Finished." % datetime.now().time())

    else:
        print("No valid password found") # this should never happen



if __name__ == "__main__":
    find_valid_passwords()