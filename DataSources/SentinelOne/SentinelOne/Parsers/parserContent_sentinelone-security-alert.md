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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"_time":\s{0,100}"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
    """"username":\s{0,100}"(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+)"""",
    """"classification":\s{0,100}"({alert_type}[^"]+)""",
    """"filePath":\s{0,100}"({malware_url}[^"]+)""",
    """"fileContentHash":\s{0,100}"({sha1}[^"]+)""",
    """"rank":\s{0,100}(null|({alert_severity}[^",]+))""",
    """"agentDomain":\s{0,100}"({src_domain}[^"]+)""",
    """"agentComputerName":\s{0,100}"({src_host}[^"]+)""",
    """"fileExtensionType":\s{0,100}"(None|Unknown|({file_type}[^"]+))""",
    """"agentOsType":\s{0,100}"({os}[^"]+)""",
    """"annotation":\s{0,100}"({additional_info}[^"]+)""",
    """"threatName":\s{0,100}"({alert_name}[^"]+)""",
    """"agentIp":\s{0,100}"({src_ip}[^"]+)""",
    """"fileDisplayName":\s"({file_name}[^"]+)""",
  ]
  DupFields = ["file_name->process_name", "malware_url->process"]
}
```