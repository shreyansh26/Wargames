def test(inp):
    if inp == 2:
        print("yes")
    else:
        print("no")

print dir(test.func_code.co_consts)
