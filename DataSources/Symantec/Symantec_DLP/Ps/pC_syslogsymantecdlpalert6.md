#### Parser Content
```Java
{
Name = syslog-symantec-dlp-alert-6
   Vendor = Symantec
   Product = Symantec DLP
   Lms = Direct
   DataType = "dlp-alert"
   TimeFormat = "MMM dd, yyyy HH:mm:ss"
   Conditions = [  """,incident_id=""", """,block=""", """,policy=""", """,monitor_name=""", """,subject="""   ]
   Fields = [
     """\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[^\s]{1,2000})\s{1,100}application""",
     """occurred_on="{1,20}(({time}.+?)\s{1,100}(:?AM|PM|am|pm))""",
     """incident_id="{1,20}({alert_id}[^"]{1,2000})""",
     """subject="{1,20}({subject}.+?)\s{0,100}"""",
     """policy_rules="{1,20}({alert_type}[^"]{1,2000})""",
     """protocol="{1,20}({protocol}[^"]{1,2000})""",
     """severity="{1,20}({alert_severity}[^"]{1,2000})""",
     """(policy|Policy)="{1,20}({alert_name}[^"]{1,2000})""",
     """sender="{1,20}(({sender}[^"@]{1,2000}@[^"@]{1,2000})|({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|(WinNT:\/+)?({domain}[^\\\/]{1,2000})(\\|\/)({user}[^"]{1,2000}))"{1,20}""",     
     """block="{1,20}({outcome}[^"]{1,2000})""",
     """recipients="{1,20}((({target}http.+?)"{1,20})|({recipients}({recipient}[^,"]{1,2000})[^"]{0,2000})"{1,20})""",
     """attachment="{1,20}({attachments}[^"]{1,2000})\s{1,100}""",
     """match_count="{1,20}({match_count}[^"]{1,2000})""",
     ]
}
```