#### Parser Content
```Java
{
Name = cef-defender-graph-security-alert
   Vendor = Microsoft
   Product = Microsoft Defender ATP
   Lms = Splunk
   DataType = "alert"
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
   Conditions = ["""CEF:""", """|security-threat-detected|""", """dproc=Graph Security Alerts""", """provider":"Microsoft Defender ATP""" ]
   Fields = [
     """\s({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s+({host}[^\s]+)\s+Skyformation""",
     """"+hostStates"+:.+?fqdn"+:"+({host}[^"]+)""",
     """"+hostStates"+:.+?privateIpAddress"+:"+({src_ip}[^"]+)""",
     """"+hostStates"+:.+?publicIpAddress"+:"+({dest_ip}[^"]+)""",
     """"+hostStates"+:.+?riskScore"+:"+({alert_severity}[^"]+)""",
     """"+hostStates"+:.+?accountName"+:"+({user}[^"]+)""",
     """"+hostStates"+:.+?domainName"+:"+({domain}[^"]+)""",
     """"+hostStates"+:.+?userPrincipalName"+:"+({user_email}[^"]+)""",
     """recommendedActions"+.+?severity"+:"+({alert_severity}[^"]+)""",
     """recommendedActions"+.+?title"+:"+({alert_name}[^"]+)""",
     """"+category"+:"+({alert_type}[^"]+)""",
     """"+fileHash"+.+?hashValue"+:"+({sha1_sum}[^"]+)""",
     """"+description"+:"+({additional_info}[^"]+)\s+""",
     """"+sourceMaterials"+:\["+({malware_url}[^"]+)"""
   ]
}
```