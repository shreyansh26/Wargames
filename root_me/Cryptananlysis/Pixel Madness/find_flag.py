from PIL import Image

image_enc = open('input2', 'r').readlines()
print(image_enc)

pixels = []

for row in image_enc:
    row = row.strip()
    row = row.split('+')
    step = 0
    for column in row:
        column = column.split('x')
        if column[0] == '0':
            for i in range(int(column[1])):
                step += 1
                pixels.append((255,255,255))
                if step == 100:
                    break

        else:
            for i in range(int(column[1])):
                step += 1
                pixels.append((0,0,0))

image_out = Image.new("RGB", (100, len(image_enc)), "white")
image_out.putdata(pixels)
image_out.save('sol2.png')

