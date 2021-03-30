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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"_time":\s*"({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)""",
    """"username":\s*"(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+)"""",
    """"classification":\s*"({alert_type}[^"]+)""",
    """"filePath":\s*"({malware_url}[^"]+)""",
    """"fileContentHash":\s*"({sha1}[^"]+)""",
    """"rank":\s*(null|({alert_severity}[^",]+))""",
    """"agentDomain":\s*"({src_domain}[^"]+)""",
    """"agentComputerName":\s*"({src_host}[^"]+)""",
    """"fileExtensionType":\s*"(None|Unknown|({file_type}[^"]+))""",
    """"agentOsType":\s*"({os}[^"]+)""",
    """"annotation":\s*"({additional_info}[^"]+)""",
    """"threatName":\s*"({alert_name}[^"]+)""",
    """"agentIp":\s*"({src_ip}[^"]+)""",
  ]
}
```