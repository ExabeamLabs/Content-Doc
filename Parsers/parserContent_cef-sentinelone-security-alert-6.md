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
     """"classification":\s*"+({alert_name}[^"]+)"""",
     """"agentIp":\s*"+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
     """"fileDisplayName":\s*"+({file_name}[^"]+)"""",
     """"filePath":\s*"+({malware_url}[^"]+)"""",
     """"agentDomain":\s*"+({src_domain}[^"]+)"""",
     """"agentComputerName":\s*"+({src_host}[^"]+)"""",
     """ msg=({additional_info}.*?)\s+\w+="""
     """"fileExtensionType":(\s*"+None|null|\s*"+({file_type}[^"]+)")""",
     """outcome=({outcome}[^,*\\\s"*]+)""",
     """dpriv=({alert_type}\w+)\s+\w+="""
     """ext_rank=({alert_severity}\d+)"""     
     """ext_username=({user_fullname}\w+\s+\w+)\s+\w+="""
     """ext_username=({user}\w+)\s+\w+="""
     """ext_username=({domain}[^\s=]+?)\\({user}[^\\=\s]+?)\s+\w+="""
  ]
}
```