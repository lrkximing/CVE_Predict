import os
import json
import shutil
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import subprocess
import ast
plt.rcParams["font.sans-serif"]=["SimHei"]
plt.rcParams["axes.unicode_minus"]=False

# 获取git提交不同
def get_commits_diff(path, trend_path, filename):
    # 获取某一cve json文件的所有历史提交版本信息
    output = subprocess.check_output(f"git log -- {path}", shell=True).decode()
    with open(os.path.join(trend_path, filename), 'w') as f:
        commits_id = [] #各历史版本的提交id
        dates = [] #各历史版本的提交时间
        commit_info = {} #存储到json的信息
        lines = output.split("\n")
        for line in lines:
            if 'commit' in line and len(line.split())==2:
                commits_id.append(line.split()[1])
            if 'Date:' in line:
                dates.append(" ".join(line.split()[1:-1]))
        commits_id.reverse()
        dates.reverse()
        # commits_id.append("master")
        # dates.append("Now")
        #print(f"output:{output} \ncommits:{commits_id} \ndate:{dates} ")
        commit_info['commits'] = commits_id
        commit_info['date'] = dates
        try:
            if len(commits_id)>1:
                for i in range(len(commits_id)-1):
                        diff_content = subprocess.check_output(f"git diff  {commits_id[i]} {commits_id[i+1]}  -- {path}", shell=True).decode()
                        diff_list = diff_content.split("\n")[5:]
                        diff_description = "no modification"
                        diff_score = "no modification"
                        add_diff = [modify.replace("+","").replace("{","").replace("}","").replace("[","").replace("]","").replace(",","") for modify in diff_list if not modify.startswith("-") and "\"" in modify]
                        add_str = "\n".join(add_diff)
                        print(add_str)
                        for j,modify in enumerate(add_diff):
                            if  "description" in modify and "description_data" in add_diff[j+1] and "value" in add_diff[j+3]:          
                                diff_description = " ".join(add_diff[j+3].replace("\"","").strip().split(":")[1:])       
                            if  "baseScore" in modify:
                                diff_score = modify.replace("\"","").strip().split(":")[1]   
                        commit_info[f'{i+1}_th diff_description'] = diff_description
                        commit_info[f'{i+1}_th diff_score'] = diff_score         
                        print(f"{i}: description={diff_description}\nscore={diff_score}")
            else:
                #print(f"只有一次提交{filename}")
                commit_info['modification'] = "False"
            json.dump(commit_info, f, indent=2)
        except Exception:
            print(f"错误追溯文件：{filename}")
            

#get_commits_diff("2019/1xxx/CVE-2019-1758.json", "./trend", "CVE-2019-1758.json")

# 生成cve数据集
def select_pub(path, trend_path, save_path):
    for folder in os.listdir(path):
        if '20' in folder:
            for folder_sub in os.listdir(os.path.join(path, folder)):
                for file in os.listdir(os.path.join(os.path.join(path, folder), folder_sub)):
                    try:
                        with open(os.path.join(os.path.join(os.path.join(path, folder), folder_sub), file), 'r', encoding='utf-8') as json_file:                        
                            data = json.load(json_file)
                            if (
                                data['CVE_data_meta']['STATE'] == 'PUBLIC'
                                and 'impact' in data
                                and 'cvss' in data['impact']
                                and 'baseScore' in data['impact']['cvss']
                                and data['impact']['cvss']['baseScore']
                                not in ['null', 'dep']
                            ):
                                get_commits_diff(os.path.join(os.path.join(os.path.join(path, folder), folder_sub), file), trend_path, file)
                                shutil.copy(os.path.join(os.path.join(os.path.join(path, folder), folder_sub), file), os.path.join(save_path, file))                           

                    except UnicodeDecodeError:
                        with open(os.path.join(os.path.join(os.path.join(path, folder), folder_sub), file), 'r') as json_file: 
                            data = json.load(json_file)
                            if (
                                data['CVE_data_meta']['STATE'] == 'PUBLIC'
                                and 'impact' in data
                                and 'cvss' in data['impact']
                                and 'baseScore' in data['impact']['cvss']
                                and data['impact']['cvss']['baseScore']
                                not in ['null', 'dep']
                            ):
                                get_commits_diff(os.path.join(os.path.join(os.path.join(path, folder), folder_sub), file), trend_path, file)
                                shutil.copy(os.path.join(os.path.join(os.path.join(path, folder), folder_sub), file), os.path.join(save_path, file))
                  
                    except TypeError:
                        print(f"文件类型错误{file}")


#select_pub("./", './trend','./data')


# 获取git仓库的修改链
def get_commit_files(path, save_path):
    # 获取git仓库18年之前的提交id
    log = subprocess.check_output("git log --stat --after='2018-1-1'").decode()
    with open('./cvelisttrend.txt','w') as f:
        lines = log.split("\n")
        commits_id = []
        for line in lines:
            if 'commit' in line and len(line.split())==2:
                commits_id.append(line.split()[1])
                f.write(line.split()[1]+"\n")
    #print(len(commits_id), commits_id[-1])
    commits_id.reverse()   
    for i in range(len(commits_id)-1):
        try:
            if i+1 == len(commits_id)-2:
                subprocess.check_output(f"git checkout {commits_id[i+1]}")
                for dir in os.listdir(path):
                    if '20' in dir and int(dir)>=2018:
                        for jsonfile in os.listdir(os.path.join(path, dir)):
                            shutil.copy(os.path.join(os.path.join(path, dir), jsonfile), os.path.join(os.path.join(save_path, commits_id[i+1]), jsonfile))
            else:
                output = subprocess.check_output(f"git log {commits_id[i]}..{commits_id[i+1]} --stat").decode() #有问题
                infos = output.split("\n")
                for idex, info in enumerate(infos):     
                    if "files changed" in info:
                        changed_len = int(info.split()[0])
                        for j in range(idex-changed_len,idex):
                            #print(infos[j])
                            year = int(infos[j].split('/')[0])
                            if year>=2018:
                                subprocess.check_output(f"git checkout {commits_id[i+1]}")
                                file = infos[j].split('|')[0].strip()
                                filename = file.split('/')[-1]
                                if not os.path.exists(os.path.join(save_path,commits_id[i+1])):
                                    os.makedirs(os.path.join(save_path,commits_id[i+1]))
                                shutil.copy(file, os.path.join(os.path.join(save_path,commits_id[i+1]),filename))
                            #print(year)                                                                                                                            
        except Exception:
            with open('./errow_commit.txt','a') as e:
                e.write(commits_id[i+1]+"\n")
                e.flush()
        
#get_commit_files("./cvelist", "./database")


# 统计每次提交更改文件的数量
def statistics_cve():
    log = subprocess.check_output("git log --stat --after='2018-1-1'").decode()
    with open('./cvelist.txt','w') as cvelist:
        lines = log.split("\n")
        commits_id = []
        for line in lines:
            if 'commit' in line and len(line.split())==2 and len(line.split()[1])==40:
                commits_id.append(line.split()[1])
                cvelist.write(line.split()[1]+"\n")
    
 
    #print(len(commits_id), commits_id[-1])
    commits_id.reverse()
    print(len(commits_id) )
    for i in range(len(commits_id)-1):
        if i == len(commits_id)-2:
            break
        output = subprocess.check_output(f"git diff {commits_id[i]} {commits_id[i+1]} --stat").decode() #获取commits_id[i+1]的修改文件
        infos = output.split("\n")
        with open('./cvelisttrend.txt','a') as f:
            count = 0
            for info in infos:  
                info = info.strip()   
                if "/" in info and "|" in info and info.startswith("20"):
                    year = int(info.split('/')[0])
                    if year>=2018:
                        count+=1
            f.write(commits_id[i+1]+"   "+ str(count) +"\n")                   
            f.flush()                                                                                               

#statistics_cve()


# 得到从2018年至今，cve文件的修改次数和修改id
def get_fix(path):
     for folder in os.listdir(path):
        if '20' in folder and int(folder)>=2019:
            for folder_sub in os.listdir(os.path.join(path, folder)):
                for file in os.listdir(os.path.join(os.path.join(path, folder), folder_sub)):
                    #print(os.path.join(os.path.join(folder, folder_sub), file))
                    out = subprocess.check_output(f"git log -- {os.path.join(os.path.join(folder, folder_sub), file)}").decode()
                    lines = out.split("\n")
                    with open("./cvefix.txt", 'a') as f:
                        commit_ids = []
                        for line in lines:
                            if 'commit' in line and len(line.split())==2 and len(line.split()[1])==40:
                                commit_ids.append(line.split()[1])  #列表中最上面的是最新的
                        f.write(file+"  "+ str(len(commit_ids))+ "\n")
                        f.flush()
                                
get_fix("./")


# CVE统计分析
def cve_data_analysis(path):   
    print(f"CVE文件数目：{len(os.listdir(path))}")
    word = []
    lengths = []
    severitys = []
    for file in os.listdir(path):
        try:
            with open(os.path.join(path, file), 'r') as json_file:
                data = json.load(json_file)
                description = data['description']['description_data'][0]['value']
                word.append(description.split())
                lengths.append(len(description.split()))
                if float(data['impact']['cvss']['baseScore']) >= 9.0:
                    severitys.append('Critical')
                elif float(data['impact']['cvss']['baseScore']) >= 7.0:
                    severitys.append('High')
                elif float(data['impact']['cvss']['baseScore']) >= 4.0:
                    severitys.append('Medium')    
                else:
                    severitys.append('Low')    
    
        except UnicodeDecodeError:
            with open(os.path.join(path, file), 'r', encoding='utf-8') as json_file:
                data = json.load(json_file)
                description = data['description']['description_data'][0]['value']
                word.append(description.split())
                lengths.append(len(description.split()))
                if float(data['impact']['cvss']['baseScore']) >= 9.0:
                    severitys.append('Critical')
                elif float(data['impact']['cvss']['baseScore']) >= 7.0:
                    severitys.append('High')
                elif float(data['impact']['cvss']['baseScore']) >= 4.0:
                    severitys.append('Medium')    
                else:
                    severitys.append('Low')  


    print(f"CVE描述平均单词数目：{sum(lengths)/len(lengths)} \nCVE描述最大单词数目：{max(lengths)} \nCVE描述最小单词数目：{min(lengths)} \n单词范围：{len(list(set(word)))}")
    # 显示cve描述的分布情况
    bins = np.arange(0, 601, 50)
    s = pd.cut(lengths, bins)
    #print(s.value_counts())
    values = s.value_counts().values
    labels = [f"{str(i)}-{str(i+50)}" for i in range(0, 600, 50)]
    #print(labels)
    plt.figure(figsize=(10, 4), dpi=200)
    des_rects = plt.bar(labels,values)
    for rect in des_rects:
        height = rect.get_height() 
        plt.text(
            rect.get_x()+rect.get_width()/2,
            height,
            f'{int(height)}',
            horizontalalignment='center',
            verticalalignment='bottom',
            size=10,
            family="Times new roman",
        )
    plt.title("CVE描述长度分布情况")
    plt.ylabel('频数')
    plt.xlabel('区间')
    plt.show()

    #显示cve严重程度的分布情况
    critical = severitys.count('Critical')
    high = severitys.count('High')
    medium = severitys.count('Medium')
    low = severitys.count('Low')
    x_s = ['Low','Medium','High','Critical']
    y_s = [low,medium,high,critical]
    plt.plot(x_s, y_s, lw=4, ls='-', c='b', alpha=0.1)
    for x, y in zip(x_s, y_s):
         plt.text(x, y, str(y), horizontalalignment='center', verticalalignment='bottom')
    plt.ylabel('数量')
    plt.xlabel('CVSS评级')
    plt.plot()
    plt.show()

#cve_data_analysis("./cvelist/database")


