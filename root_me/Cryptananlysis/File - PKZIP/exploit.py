import zipfile

def extract(zipfile):
  for passwd in range(00000,99999):
    # print passwd
    try:
      zipfile.extractall(pwd=str(passwd))
      return passwd
    except:
      pass

def solve():
  passwd = ''
  zFile = zipfile.ZipFile('ch5.zip')
  passwd = extract(zFile)
  if passwd:
    print "Password: %s" % passwd

solve()