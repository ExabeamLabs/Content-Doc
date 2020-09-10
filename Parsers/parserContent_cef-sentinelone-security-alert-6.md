#### Parser Content
```Java
{
Name = cef-sentinelone-security-alert-6
  Vendor = SentinelOne
  Product = SentinelOne
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """SkyFormation Cloud Apps Security""", """security-threat-detected""", """destinationServiceName=SentinelOne""", ]
  Fields = [
     """exabeam_host=({host}[^\s]+)""",
     """"createdAt":\s*"({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)""",
     """"classification":\s*"({alert_name}[^"]+)""",
     """"agentIp":\s*"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
     """"fileDisplayName":\s*"({file_name}[^"]+)""",
     """"filePath":\s*"({malware_url}[^"]+)""",
     """"agentDomain":\s*"(unknown|({src_domain}[^"]+))""",
     """"agentComputerName":\s*"({src_host}[^"]+)""",
     """\smsg=({additional_info}.*?)\s+\w+=""",
     """"fileExtensionType":(\s*"None|null|\s*"+(Unknown|({file_type}[^"]+))")""",
     """outcome=({outcome}[^,*\\\s"*]+)""",
     """dpriv=({alert_type}\w+)\s+\w+=""",
     """username":"((NT AUTHORITY|({domain}[^\\"]+))\\+)?(SYSTEM|({user}[^"]+))",""",
     """dproc=({location}.+?)\s+\w+=""",
     """cat=({category}.+?)\s+\w+=""",
     """app=({app}.+?)\s+\w+=""",
     """fileHash=({md5}.+?)\s\w+=""",
     """"rank":({alert_severity}\d+)"""
  ]
}
```