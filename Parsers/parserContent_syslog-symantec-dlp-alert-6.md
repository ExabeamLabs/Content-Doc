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
     """\w+\s*\d+\s*\d+:\d+:\d+\s+({host}[^\s]+)\s+application""",
     """occurred_on="+(({time}.+?)\s+(:?AM|PM|am|pm))""",
     """incident_id="+({alert_id}[^"]+)""",
     """subject="+({subject}.+?)\s*"""",
     """policy_rules="+({alert_type}[^"]+)""",
     """protocol="+({protocol}[^"]+)""",
     """severity="+({alert_severity}[^"]+)""",
     """(policy|Policy)="+({alert_name}[^"]+)""",
     """sender="+(({sender}[^"@]+@[^"@]+)|({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|(WinNT:\/+)?({domain}[^\\\/]+)(\\|\/)({user}[^"]+))"+""",     
     """block="+({outcome}[^"]+)""",
     """recipients="+((({target}http.+?)"+)|({recipients}({recipient}[^,"]+)[^"]*)"+)""",
     """attachment="+({attachments}[^"]+)\s+""",
     """match_count="+({match_count}[^"]+)""",
     ]
}
```