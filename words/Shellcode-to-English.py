import sys
import random
import os

def generate_words():
    script_dir = os.path.dirname(os.path.abspath(__file__))  # 获取当前脚本所在的目录
    words_file = os.path.join(script_dir, 'words_alpha.txt')
    with open(words_file, 'r') as f:
        words = f.read().splitlines()
    random_words = random.sample(words, 256)
    return random_words


outputlength = 0

dataset = generate_words()

length = len(dataset)
print(length)
payload = open(sys.argv[1], "rb").read()

outputlength = len(payload)
final = [""] * outputlength
iterator = 0

for c in payload:
    if c < length:
        final[iterator] = dataset[c]
    iterator += 1

#print('{"' + '","'.join(final) + '"}')
length = len(final)
output = ""
for i in range(length):
    word = final[i]
    output += '\t"' + word + '",'
    if (i + 1) % 30 == 0:
        output += "\\\n"

print(output)

# Write the output to enc2.bin
script_dir = os.path.dirname(os.path.abspath(__file__))  # 获取当前脚本所在的目录
words_file = os.path.join(script_dir, 'words.txt')
with open(words_file, "wb") as file:
    file.write(output.encode())

dataset_str = '","'.join(dataset)
dataset_str ='"'+dataset_str+'"'

dataset_file= os.path.join(script_dir, 'dataset.txt')
with open(dataset_file, "wb") as file:
    file.write(dataset_str.encode())