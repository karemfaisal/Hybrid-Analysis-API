## Hybrid Analysis API

*This script allow users to retrieve data using Hybrid Analysis API,It can search for malware family or malware name or hash*
*you can give it malware file name ex: mimikatz and ask for IMP hash for all files contains mimikatz in it's files name on Hybrid Analysis*

### How to use

```powershell
./Hybrid.ps1 -API <API> -filename mimikatz -result IMPhash,sha256
```

```powershell
./Hybrid.ps1 -API <API> -filename mimikatz,emotet -result IMPhash,sha256,hosts,domains
```

```powershell
./Hybrid.ps1 -API <API> -filename (get-content -Path malwares.txt) -result (get-content -Path result.txt)
```


of course this script could be imported as module

```powershell
Import-Module -Path "Path to Hybrid API.ps1"
```
**for long time Importing** add the above command to  Microsoft. PowerShell_profile.ps1 which could be found by running $profile in the PowerShell and create the path if it's not existed



### Output of the script

![1](https://raw.githubusercontent.com/karemfaisal/Hybrid-Analysis-API/master/Misc/output1.JPG)

![2](https://raw.githubusercontent.com/karemfaisal/Hybrid-Analysis-API/master/Misc/output2.JPG)

you can search by hashes, if you supply -VT_API, script will search hashes in virus total, if you didn't then the script will use the supplied Hybrid Analysis API

*the following script will use VT_API for hashes and Hybrid Analysis for filename*

```powershell
./Hybrid-API -VT_API <VT_API>,<VT_API> -hash <hash1>,<hash2>,<hash3> -API <API> -filename mimikatz -result imphash
```

![output3](https://raw.githubusercontent.com/karemfaisal/Hybrid-Analysis-API/master/Misc/output3.JPG)

### Authors

* **Karem Ali**  - [twitter](https://twitter.com/KaremAliFaisal) [LinkedIn](https://www.linkedin.com/in/karem-ali-14a14910b/l)



### To-Do

- searching using vx_family
- ~~searching using list of hashes~~



