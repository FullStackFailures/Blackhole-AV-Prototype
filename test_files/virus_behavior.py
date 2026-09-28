print("👾 Virus started")

# create file
open("secret.txt", "w").write("stolen data")

# modify file
open("secret.txt", "a").write("\nmore data")

# delete file
import os
os.remove("secret.txt")
