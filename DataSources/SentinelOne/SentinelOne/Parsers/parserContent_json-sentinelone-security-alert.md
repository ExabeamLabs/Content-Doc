#### Parser Content
```Java
{
Name = json-sentinelone-security-alert
  Vendor = SentinelOne
  Product = SentinelOne
  Lms = Splunk
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"s1domain":""" ,""""siteId":""", """"_time":""", """"accountId":"""]
  Fields = [
    """"_time":\s*"({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)"""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"threatName"+:\s*"+({alert_name}[^"]+)""",
    """"(username|lastLoggedInUserName)"+:\s*"+({user}[^"]+)""",
    """"accountName"+:\s*"+({account}[^"]+)""",
    """"(description|primaryDescription)"+:\s*"+({additional_info}[^"]+)""",
    """"(computerName|agentComputerName)"+:\s*"+({src_host}[^"]+)""",
    """"(agentIp|externalIp)"+:\s*"+({dest_ip}[^"]+)""",
    """"(agentOsType|osName)"+:\s*"+({os}[^"]+)""",
    """"fileDisplayName"+:\s*"+({file_name}[^"]+)""",
    """"filePath"+:\s*"+({malware_url}[^"]+)""",
    """"domain"+:\s*"+({domain}[^",]+)""",
    """"uuid"+:\s*"+({uuid}[^"]+)""",
    """"inet":\s*\["({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"]""",
  ]
}
```