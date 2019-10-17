function Hybrid-API{
<#

.SYNOPSIS

This script allow users to retrieve  data using Hybrid Analysis API,It can search for malware family or malware name or hash
you can give it malware file name ex: mimikatz and ask for IMPhash for all files contains mimikatz in it's files name on Hybrid Analysis


Function: Hybrid Analysis API
Author: Karem Ali
Required Dependencies: Hybrid Analysis API key, Powershell V3 or higher
Version: 1.0

.DESCRIPTION

Helpful functions for Hybrid Analysis API
.PARAMETER API

Mandatory: it's Mandatory to able to talk with Hybrid Analysis API

.PARAMETER vx_family

Switch: search for this vx_family on Hybrid Analysis

.PARAMETER filename

Switch: search for file name on Hybrid Analysis

.PARAMETER result

Optional: retrive only the result you asked for Values = {imphash,sha256,sha1,md5,,ssdeep,submit_name, type_short, hosts,domains,vx_family,threat_score,av_detect}

.PARAMETER output_file

Optional, path of output file
	
.EXAMPLE

./Hybrid.ps1 -API <API> -filename mimikatz -result IMPhash,sha256

.EXAMPLE

./Hybrid.ps1 -API <API> -filename mimikatz,emotet -result IMPhash,sha256,hosts,domains

.EXAMPLE

./Hybrid.ps1 -API <API> -filename (get-content -path malwares.txt) -result (get-contetn -path result.txt)

.NOTES
You have to set execution policy in powershell to bypass

.LINK

http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
#>


    [CmdletBinding()]
    Param(
        [string[]] $filename,
        [string[]] $vx_family,
        [string[]] $hash,
        [string[]] $API,
        [string[]] $result
        
       

    )
   
process{
   $result_Data = New-Object System.Collections.Generic.List[string]
   $result_obj = New-Object System.Collections.Generic.List[object]
   $attacks = New-Object System.Collections.Generic.List[string]
    if($filename){

        foreach($f in $filename)
        {
            Write-Host -ForegroundColor Green "`n Results for $f `n --------------------"
            $y = Invoke-RestMethod "https://www.hybrid-analysis.com/api/v2/search/terms?_timestamp=1570613873480" -Headers @{'accept' = 'application/json'; 'user-agent' = 'Falcon Sandbox' ; 'Content-Type' = 'application/x-www-form-urlencoded' ; 'api-key' = "$API"} -Method Post -Body @{'filename' = "$f" } 
            
            if($result){
                
                    if($result -match "imphash")
                    {
                         Write-Host -ForegroundColor Green "Note: Imphash is Just for executables, if it's ps1 or dll ..etc, it will not have ImpHash"
                    }

                      
                            foreach($r in ($y.result |  select -ExpandProperty sha256))
                              {
                                   $gvx = ((Invoke-WebRequest "https://www.hybrid-analysis.com/api/v2/search/hash?_timestamp=1570612575135" -Headers @{'accept' = 'application/json'; 'user-agent' = 'Falcon Sandbox' ; 'Content-Type' = 'application/x-www-form-urlencoded' ; 'api-key' = "$API"} -Method Post -Body @{'hash' = "$r"}).content | ConvertFrom-Json)
                                   if($gvx.Length -gt 1)
                                   {
                                         foreach($t in $gvx)
                                         {
                                                $result_obj.Add($t)
                                         }
                                   }
                                   else
                                   {
                                    $result_obj.Add($gvx)

                                   }
                              }
                                                     
                          foreach($res in $result)
                         {
                                
                             for($i=0; $i -lt $result_obj.Count ; $i++)
                                {
                                    $result_Data.Add($result_obj[$i].$res)
                                }

                                if($res -match "hosts" -or $res -match "domains")
                                {
                                        $x = ($result_obj | select $res -Unique).$res | select -Unique
                                        if($x.count -eq 0)
                                        {
                                            Write-Host -ForegroundColor Green "There are no $res associated with the malware"
                                        }
                                        else
                                        {
                                            Write-Host "`n $res `n ---------"
                                            $x
                                        }
                                       
                                        $result_Data.Clear()
                                }
                                elseif($res -match "mitre_attcks")
                                {
                                        $attacks = New-Object System.Collections.Generic.List[string]
                                        foreach($obj in $result_obj)
                                        {
                                            foreach($attck in (($obj | select mitre_attcks).mitre_attcks | select -Unique -ExpandProperty attck_id))
                                            {
                                                    $attacks.Add($attck)
                                            }
                                        }
                                        Write-Host -ForegroundColor Green "`n Those are the most attack tactics used by $f"
                                        # Format-Table -AutoSize fixed the problem that the belows command runs late, it seems that Format-Table -AutoSize fixes many problems in group-object
                                        $attacks | Group-Object| Select-Object count,name | Sort-Object -Descending count | Format-Table -AutoSize
                                       
                                }
                                else
                                {
                                    Write-Host -ForegroundColor Green "`n$res for $f`n"
                                    # to solve the problem when using two consiectutive group-object cmdlt, I used | format-table -Autosize
                                    $result_Data | where {$_ -ne ""} | Group-Object | Select-Object -Property count,name | Sort-Object -Descending count| Format-Table -AutoSize 
                                    $result_Data.Clear()
                                }
                        }
  
        

            }
            else{
                Write-Host -ForegroundColor Green "Note:- you didn't specifiy -result "
                Write-Host -ForegroundColor Green "Count of Samples:"$y.result.Length
                $y.result | Group-Object -Property vx_family | Select-Object count,name | Sort-Object -Descending count 
      

            }
        }



    }

    if($vx_family){


        Write-Host -ForegroundColor Green "this feature will be added soon"


    }
}
}