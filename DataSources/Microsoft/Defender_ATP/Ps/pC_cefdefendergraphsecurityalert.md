#### Parser Content
```Java
{
Name = cef-defender-graph-security-alert
   Vendor = Microsoft
   Product = Defender ATP
   Lms = Splunk
   DataType = "alert"
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
   Conditions = ["""CEF:""", """|security-threat-detected|""", """dproc=Graph Security Alerts""", """provider":"Microsoft Defender ATP""" ]
   Fields = [
     """\s({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)\s{1,100}[^\s]{1,2000}\s{1,100}Skyformation""",
     """"{1,20}hostStates"{1,20}:[^\}\]]{1,2000}?fqdn"{1,20}:"{1,20}({host}[^"]{1,2000})""",
     """"{1,20}hostStates"{1,20}:[^\}\]]{1,2000}?privateIpAddress"{1,20}:"{1,20}({src_ip}[A-Fa-f:\d.]{1,2000})"""",
     """"{1,20}hostStates"{1,20}:[^\}\]]{1,2000}?publicIpAddress"{1,20}:"{1,20}({dest_ip}[A-Fa-f:\d.]{1,2000})"""",
     """"{1,20}hostStates"{1,20}:[^\}\]]{1,2000}?riskScore"{1,20}:"{1,20}({alert_severity}[^"]{1,2000})""",
     """"{1,20}hostStates"{1,20}:[^=]{1,2000}?accountName"{1,20}:"{1,20}({user}[^"]{1,2000})""",
     """"{1,20}hostStates"{1,20}:[^=]{1,2000}?domainName"{1,20}:"{1,20}({domain}[^"]{1,2000})""",
     """"{1,20}hostStates"{1,20}:[^=]{1,2000}?userPrincipalName"{1,20}:"{1,20}({user_email}[^@"]{1,2000}@[^"]{1,2000})"""",
     """recommendedActions"{1,20}[^=]{1,2000}?severity"{1,20}:"{1,20}({alert_severity}[^"]{1,2000})""",
     """recommendedActions"{1,20}[^=]{1,2000}?title"{1,20}:"{1,20}({alert_name}[^"]{1,2000})""",
     """"{1,20}category"{1,20}:"{1,20}({alert_type}[^"]{1,2000})""",
     """"{1,20}fileHash"{1,20}[^\}\]]{1,2000}?hashValue"{1,20}:"{1,20}({sha1_sum}[^"]{1,2000})""",
     """"{1,20}description"{1,20}:"({additional_info}[^"]{1,2000}?)\s{0,100}"""",
     """"{1,20}sourceMaterials"{1,20}:\["{1,20}({additional_info}[^"]{1,2000})""",
     """"id"{1,20}:"{1,20}({alert_id}[^"]{1,2000})""""
   ]


}
```