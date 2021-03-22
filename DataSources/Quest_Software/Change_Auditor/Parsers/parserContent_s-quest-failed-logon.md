#### Parser Content
```Java
{
Name = s-quest-failed-logon
  Vendor = Quest Software
  Product = Change Auditor
  Lms = Direct
  DataType = "failed-logon"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """Quest Software""", """Change Auditor""", """|Logon Activity|User failed to authenticate through""", """categoryOutcome=Failed""" ]  
  Fields = [
     """dvc=({dest_ip}[A-Fa-f:\d.]+)""",
     """\sdomain=({domain}[^\s]+)""",
     """\sevent=({event_name}[^=]+)\s\w+=""",
     """logonFailureReason=({failure_reason}[^=]+)\s\w+=""",
     """dvchost=({host}[^\s]+)""",
     """logonType=({logon_type}[^\s]+)""",
     """categoryOutcome=({outcome}[^\s]+)""",
     """shost=({src_host}[^\s]+)""",
     """src=({src_ip}[A-Fa-f:\d.]+)""",
     """\sstart=({time}\w+\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
     """\suser=(({domain}[^=\\]+)\\+)?({user}[^=\s]+)""",
     """userPrincipalName=(({user_email}[^\s=@]+@[^@\s=]+)|({user}[^\s=]+))""",
     """userMail=({user_email}[^\s=@]+@[^@\s=]+)""",
     """suid=({user_sid}[^\s]+)"""
  ]
}
```