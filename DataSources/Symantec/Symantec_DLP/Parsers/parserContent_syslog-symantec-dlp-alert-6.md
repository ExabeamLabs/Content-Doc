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
     """\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[^\s]+)\s{1,100}application""",
     """occurred_on="{1,20}(({time}.+?)\s{1,100}(:?AM|PM|am|pm))""",
     """incident_id="{1,20}({alert_id}[^"]+)""",
     """subject="{1,20}({subject}.+?)\s{0,100}"""",
     """policy_rules="{1,20}({alert_type}[^"]+)""",
     """protocol="{1,20}({protocol}[^"]+)""",
     """severity="{1,20}({alert_severity}[^"]+)""",
     """(policy|Policy)="{1,20}({alert_name}[^"]+)""",
     """sender="{1,20}(({sender}[^"@]+@[^"@]+)|({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|(WinNT:\/+)?({domain}[^\\\/]+)(\\|\/)({user}[^"]+))"{1,20}""",     
     """block="{1,20}({outcome}[^"]+)""",
     """recipients="{1,20}((({target}http.+?)"{1,20})|({recipients}({recipient}[^,"]+)[^"]*)"{1,20})""",
     """attachment="{1,20}({attachments}[^"]+)\s{1,100}""",
     """match_count="{1,20}({match_count}[^"]+)""",
     ]
}
```