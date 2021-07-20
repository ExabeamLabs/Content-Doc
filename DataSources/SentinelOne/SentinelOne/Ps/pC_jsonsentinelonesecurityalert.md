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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"threatName"{1,20}:\s{0,100}"{1,20}({alert_name}[^"]{1,2000})""",
    """"(username|lastLoggedInUserName)"{1,20}:\s{0,100}"{1,20}({user}[^"]{1,2000})""",
    """"accountName"{1,20}:\s{0,100}"{1,20}({account}[^"]{1,2000})""",
    """"(description|primaryDescription)"{1,20}:\s{0,100}"{1,20}({alert_type}[^"]{1,2000})""",
    """"(computerName|agentComputerName)"{1,20}:\s{0,100}"{1,20}({src_host}[^"]{1,2000})""",
    """"(agentIp|externalIp)"{1,20}:\s{0,100}"{1,20}({dest_ip}[^"]{1,2000})""",
    """"(agentOsType|osName)"{1,20}:\s{0,100}"{1,20}({os}[^"]{1,2000})""",
    """"fileDisplayName"{1,20}:\s{0,100}"{1,20}({file_name}[^"]{1,2000})""",
    """"filePath"{1,20}:\s{0,100}"{1,20}({malware_url}[^"]{1,2000})""",
    """"domain"{1,20}:\s{0,100}"{1,20}({domain}[^",]{1,2000})""",
    """"uuid"{1,20}:\s{0,100}"{1,20}({uuid}[^"]{1,2000})""",
    """"inet":\s{0,100}\["({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"]""",
    """"description":\s"({alert_type}[^"]{1,2000})""",
    """mitigationStatus":\s"({alert_severity}[^"]{1,2000})""", 
  ]
  DupFields = ["file_name->process_name", "file_path->process"]
}
```