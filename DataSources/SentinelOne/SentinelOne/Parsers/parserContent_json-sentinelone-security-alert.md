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
    """"_time":\s{0,100}"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)"""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"threatName"{1,20}:\s{0,100}"{1,20}({alert_name}[^"]+)""",
    """"(username|lastLoggedInUserName)"{1,20}:\s{0,100}"{1,20}({user}[^"]+)""",
    """"accountName"{1,20}:\s{0,100}"{1,20}({account}[^"]+)""",
    """"(description|primaryDescription)"{1,20}:\s{0,100}"{1,20}({alert_type}[^"]+)""",
    """"(computerName|agentComputerName)"{1,20}:\s{0,100}"{1,20}({src_host}[^"]+)""",
    """"(agentIp|externalIp)"{1,20}:\s{0,100}"{1,20}({dest_ip}[^"]+)""",
    """"(agentOsType|osName)"{1,20}:\s{0,100}"{1,20}({os}[^"]+)""",
    """"fileDisplayName"{1,20}:\s{0,100}"{1,20}({file_name}[^"]+)""",
    """"filePath"{1,20}:\s{0,100}"{1,20}({malware_url}[^"]+)""",
    """"domain"{1,20}:\s{0,100}"{1,20}({domain}[^",]+)""",
    """"uuid"{1,20}:\s{0,100}"{1,20}({uuid}[^"]+)""",
    """"inet":\s{0,100}\["({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"]""",
    """"description":\s"({alert_type}[^"]+)""",
    """mitigationStatus":\s"({alert_severity}[^"]+)""", 
  ]
  DupFields = ["file_name->process_name", "file_path->process"]
}
```