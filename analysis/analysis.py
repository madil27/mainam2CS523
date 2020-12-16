#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import pandas as pd
import seaborn as sns
from matplotlib import pyplot
import csv


# # Reading Dataset

# In[ ]:


dataname= "theia"
df = pd.read_csv("theiafinal.csv")
df.head()


# # **_RQ1 :  What are the log reduction numbers across various reduction techniques?_**

# In[ ]:


tn = df.columns[2:]
drop_count = []
for tech in tn:
    print(tech + " " + str(df[df[tech] == 2].shape[0]))
    drop_count.append(df[df[tech] == 2].shape[0])
  


# In[ ]:


data_bar = {}
data_bar["Techniques"] = tn
data_bar["Entries_Dropped"] = drop_count

# sns.set_style("grid")
sns.set(rc={'figure.figsize':(12,11)})
ax = sns.barplot(x=data_bar["Techniques"], y=data_bar["Entries_Dropped"], color="#003f5c")
ax.set_ylabel("Drop Count")
ax.set_xlabel("Techniques")
plt.savefig('drop_theia.pdf')


# # **_RQ2 :  What is the system call distribution (fileIO, process, network) of the events dropped across various techniques?_**

# In[ ]:


# http://linasm.sourceforge.net/docs/syscalls/filesystem.php#file
# syscall distribution

file_syscalls = [3,85,2, 257,303,304,319,133,259,82,264,316,76,77,285,83,258,84,79,80,81,161,78,217,212,86,87,88,263,265,267,266,95,4,5,6,262,90,91,268,92,93,94,260,132,235,261,280,21,269, 188,189,190,191,192,193,194,195,196,197,198,199,16,72,32,33,292,73,0,19,17,295,1,20,18,296,8,40,26,74,75,277,162,306,206,207,208,209,210,23,270,7,271,213,291,233,232,281,253,254,294,255,300,301,221,187,318]
process_syscalls = [56,57,58,59,322,60,231,61,247,39,110,186,112,124,109,121,111,105,102,106,104,117,118,119,120,113,114,122,123,107,108,116,115,308,160,97,302,98,314,315,144,145,142,143,203,204,146,147,148,24,141,140,251,252,12,9,11,25,10,28,149,325,151,150,152,27,324,154,126,125,205,211,218,158,134,157,317,101,310,311,312,272]
network_syscalls = [41,51,52,53,54,55,49,50,43,288,42,48,45,47,299,44,46,307,170,171,321]

# Bates -- Problem with this approach; read/write syscalls are file-based, but can also be used for networking if you pass in a Socket Descriptor instead of a File Descriptor

file_c = 0
process_c = 0
network_c = 0
other_c = 0

dist_column = []
for i in range(len(df)):
    syscall_number = df.loc[i, "NUMBER"]
    if syscall_number in file_syscalls:
        file_c += 1
        dist_column.append("file")
    elif syscall_number in process_syscalls:
        process_c += 1
        dist_column.append("process")
    elif syscall_number in network_syscalls:
        network_c += 1
        dist_column.append("network")
    else:
        other_c += 1
        dist_column.append("other")



df["syscall_type"] = dist_column

print("Total syscalls :", len(df))
print("File based system calls: ", file_c)
print("Process based system calls: ", process_c)
print("Network based system calls: ", network_c)
print("Other system calls: ", other_c)


# In[ ]:


n_count = [0] * 8
f_count = [0] * 8
p_count = [0] * 8

for i in range(len(df)):
    syscall_type = df.loc[i, "syscall_type"]
    for ind, t in enumerate(tn):
        if df.loc[i, t] == 2:
            if syscall_type == "file":
                f_count[ind] += 1
            if syscall_type == "process":
                p_count[ind] += 1
            if syscall_type == "network":
                n_count[ind] += 1
                
for i in range(len(p_count)):
    p_count[i] += (n_count[i] + f_count[i])

for i in range(len(n_count)):
    n_count[i] += f_count[i]


# In[ ]:


from matplotlib import pyplot as plt

f_count[2] = n_count[2]

#Set general plot properties
# sns.set_style("whitegrid")
sns.set_context({"figure.figsize": (13,12)})

#Plots
sns.barplot(x = tn, y = p_count, color = "#ffa600")
sns.barplot(x = tn, y = n_count, color = "#bc5090")
bottom_plot = sns.barplot(x = tn, y = f_count, color = "#003f5c")

redbar = plt.Rectangle((0,0),1,1,fc="#ffa600")
bluebar = plt.Rectangle((0,0),1,1,fc="#bc5090",  edgecolor = 'none')
greenbar = plt.Rectangle((0,0),1,1,fc="#003f5c",  edgecolor = 'none')
l = plt.legend([redbar, bluebar, greenbar], ['process', 'network', 'file'], loc=1, ncol = 3, prop={'size':16})
l.draw_frame(False)

#Optional code - Make plot look nicer
# sns.despine(left=True)
bottom_plot.set_ylabel("Drop Count")
bottom_plot.set_xlabel("Techniques")

# Set fonts to consistent 16pt size
# for item in ([bottom_plot.xaxis.label, bottom_plot.yaxis.label] +
#              bottom_plot.get_xticklabels() + bottom_plot.get_yticklabels()):
#     item.set_fontsize(12)

plt.savefig('dist_theia.pdf')


# # _**RQ3 :  What is the overlap between the various reduction techniques? How independent is one technique of the rest?**_

# In[ ]:


# Events filtered by Technique A (row) that are not filtered by Technique B (colm) divided by events filtered by A i.e (A - B) divided by (A)

unique_mat2 = []
unique_mat2.append(list(tn))
unique_mat2[0].insert(0, "Techniques")
for t1 in tn:
    temp = []
    temp.append(t1)
    for t2 in tn:
        inter_count = 0
        union_count = 0
        for i in range(len(df)):
            if (df.loc[i, t1] == 2) and not (df.loc[i, t2] == 2):
                inter_count += 1
                union_count += 1
            elif df.loc[i, t1] == 2:
                union_count += 1
        unique = round((inter_count / union_count) * 100.0, 2)
        temp.append(str(unique))
    unique_mat2.append(temp)

with open(dataname + "overlapp3.csv","w+") as my_csv:
    csvWriter = csv.writer(my_csv,delimiter=',')
    csvWriter.writerows(unique_mat2)
    
print("---- Unique Event Compression Matrix (Second variation) ----")
print("Events filtered by Technique A (row) that are not filtered by Technique B (colm) divided by events filtered by A i.e (A - B) divided by (A)\n")
print_matrix(unique_mat2)


# In[ ]:


# Events filtered by Technique A (row) that are not filtered by Technique B (colm) divided by events filtered by either A or B i.e (A - B) divided by (A ∪ B)

unique_mat = []
unique_mat.append(list(tn))
unique_mat[0].insert(0, "Techniques")
for t1 in tn:
    temp = []
    temp.append(t1)
    for t2 in tn:
        inter_count = 0
        union_count = 0
        for i in range(len(df)):
            if (df.loc[i, t1] == 2) and not (df.loc[i, t2] == 2):
                inter_count += 1
                union_count += 1
            elif df.loc[i, t1] == 2 or df.loc[i, t2] == 2:
                union_count += 1
        unique = round((inter_count / union_count) * 100.0, 2)
        temp.append(str(unique))
    unique_mat.append(temp)

with open(dataname + "overlapp2.csv","w+") as my_csv:
    csvWriter = csv.writer(my_csv,delimiter=',')
    csvWriter.writerows(unique_mat)
    
print("---- Unique Event Compression Matrix ----")
print("Events filtered by Technique A (row) that are not filtered by Technique B (colm) divided by events filtered by either A or B i.e (A - B) divided by (A ∪ B)\n")
print_matrix(unique_mat)


# In[ ]:


# Events filtered by both Technique A (row) and by Technique B (colm) divided by events filtered by either A or B i.e (A ∩ B) divided by (A ∪ B)
overlapp_matrix = []
overlapp_matrix.append(list(tn))
overlapp_matrix[0].insert(0, "Techniques")
for t1 in tn:
    temp = []
    temp.append(t1)
    for t2 in tn:
        inter_count = 0
        union_count = 0
        for i in range(len(df)):
            if( (df.loc[i,t1] == 2) and (df.loc[i,t2] == 2)):
                inter_count += 1
                union_count += 1
            elif (df.loc[i,t1] == 2 or df.loc[i,t2] == 2):
                union_count += 1
        overlapp = round((inter_count/union_count) * 100.0, 2)
        temp.append(str(overlapp))
    overlapp_matrix.append(temp)

    
with open(dataname + "overlapp1.csv","w+") as my_csv:
    csvWriter = csv.writer(my_csv,delimiter=',')
    csvWriter.writerows(overlapp_matrix)
    
print("---- Overlap Matrix ----")
print("Events filtered by both Technique A (row) and by Technique B (colm) divided by events filtered by either A or B i.e (A ∩ B) divided by (A ∪ B)\n")
print_matrix(overlapp_matrix)


# # **_RQ4 : Which set of techniques, both intuitively and experimentally, when used together provide us the maximum reduction?_**

# In[ ]:


def combinationUtil(arr, n, r,index, data, i,sub_array):  
    if(index == r):
        temp = [] 
        for j in range(r):
            temp.append(data[j])
        sub_array.append(temp)
        return
    if(i >= n): 
        return
    data[index] = arr[i] 
    combinationUtil(arr, n, r,  index + 1, data, i + 1, sub_array) 
    combinationUtil(arr, n, r, index,data, i + 1, sub_array) 

def getCombinations(arr, n, r):  
    data = list(range(r))
    sub_array = []
    combinationUtil(arr, n, r,  0, data, 0,sub_array)
    return sub_array


# In[ ]:


subset2_array = getCombinations(tn, len(tn) , 2)
subset3_array = getCombinations(tn, len(tn) , 3)


# In[ ]:


my_dict = {}
for techs in subset2_array:
    tup = (techs[0], techs[1])
    my_dict[tup] = 0

for i in range(len(df)):
    for key in my_dict:
        for t in key:
            if df.loc[i, t] == 2:
                my_dict[key] += 1
                break
    
sorted_dict2 = {k: v for k, v in sorted(my_dict.items(), reverse=True, key=lambda item: item[1])}

darray = []
for key,value in sorted_dict2.items():
    my_str = key[0] + "+" +  key[1]
    temp = [my_str,value]
    darray.append(temp)
        
    
with open(dataname + "sub2.csv","w+") as my_csv:
    csvWriter = csv.writer(my_csv,delimiter=',')
    csvWriter.writerows(darray)

sorted_dict2


# In[ ]:


my_dict = {}
for techs in subset3_array:
    tup = (techs[0], techs[1], techs[2])
    my_dict[tup] = 0

for i in range(len(df)):
    for key in my_dict:
        for t in key:
            if df.loc[i, t] == 2:
                my_dict[key] += 1
                break
    
sorted_dict = {k: v for k, v in sorted(my_dict.items(),reverse=True, key=lambda item: item[1])}

darray = []
for key,value in sorted_dict.items():
    my_str = key[0] + "+" +  key[1] + "+" + key[2]
    temp = [my_str,value]
    darray.append(temp)
        
    
with open(dataname + "sub3.csv","w+") as my_csv:
    csvWriter = csv.writer(my_csv,delimiter=',')
    csvWriter.writerows(darray)

sorted_dict


# In[ ]:


##  Algorithm : Pick the thing that offers the most compression, then with the remaining events, take the thing that offers the next compression

visited = [0] * len(df)

def find_max(data, techniques):
    # print(techniques)
    num_dict = {}
    for t in techniques:
        num_dict[t] = 0
    
    for i in range(len(data)):
        for t in techniques:
            if (visited[i] == 0):
                if (df.loc[i, t] == 2):
                    num_dict[t] += 1
    # print(num_dict)
    max_value = -1
    max_key = ""
    for key, value in num_dict.items():
        if value > max_value:
            max_value = value
            max_key = key
    
    if(max_value == 0):
        return "nothing" , 0

    for i in range(len(data)):
        if df.loc[i, max_key] == 2:
            visited[i] = 1

    return max_key, max_value


tech = [x for x in tn]
# tech.remove("DPRESERVE_SD")
# tech.remove("DPRESERVE_FD")
count = 0
while len(tech):
    max_tech, number = find_max(df, tech)
    if number == 0:
        print("All other techniques further remove no items")
        break
    tech.remove(max_tech)
    if(count == 0):
        print("Technique " + max_tech + " initially removed " + str(number) + " entries")
    else:
        print("Technique " + max_tech + " further removed " + str(number) + " from the remaining entries")
    count+=1


