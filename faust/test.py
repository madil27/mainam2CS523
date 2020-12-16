outfilename = "test2.log"
infilename = "ta1-theia-e3-official-5m.bin.log"


lines_seen = set() # holds lines already seen
outfile = open(outfilename, "w")
for line in open(infilename, "r"):
    if line not in lines_seen: # not a duplicate
        outfile.write(line)
        lines_seen.add(line)
    else:
    	print("DUPLICATE!")
outfile.close()
