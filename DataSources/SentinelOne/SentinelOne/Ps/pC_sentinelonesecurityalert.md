#### Parser Content
```Java
{
Name = sentinelone-security-alert
  Vendor = SentinelOne
  Product = SentinelOne
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"annotation": """, """"threatName": """", """"fileContentHash": """", """"fileExtensionType": """", """"s1domain": """" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"_time":\s{0,100}"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
    """"username":\s{0,100}"(({domain}[^\\\s"]{1,2000})\\+)?({user}[^\\\s"]{1,2000})"""",
    """"classification":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """"filePath":\s{0,100}"({malware_url}[^"]{1,2000})""",
    """"fileContentHash":\s{0,100}"({sha1}[^"]{1,2000})""",
    """"rank":\s{0,100}(null|({alert_severity}[^",]{1,2000}))""",
    """"agentDomain":\s{0,100}"({src_domain}[^"]{1,2000})""",
    """"agentComputerName":\s{0,100}"({src_host}[^"]{1,2000})""",
    """"fileExtensionType":\s{0,100}"(None|Unknown|({file_type}[^"]{1,2000}))""",
    """"agentOsType":\s{0,100}"({os}[^"]{1,2000})""",
    """"annotation":\s{0,100}"({additional_info}[^"]{1,2000})""",
    """"threatName":\s{0,100}"({alert_name}[^"]{1,2000})""",
    """"agentIp":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"fileDisplayName":\s"({file_name}[^"]{1,2000})""",
  ]
  DupFields = ["file_name->process_name", "malware_url->process"]
}
```