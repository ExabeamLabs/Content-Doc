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
     """dvc=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
     """\sdomain=({domain}[^\s]{1,2000})""",
     """\sevent=({event_name}[^=]{1,2000})\s\w+=""",
     """logonFailureReason=({failure_reason}[^=]{1,2000})\s\w+=""",
     """dvchost=({host}[^\s]{1,2000})""",
     """logonType=({logon_type}[^\s]{1,2000})""",
     """categoryOutcome=({outcome}[^\s]{1,2000})""",
     """shost=({src_host}[^\s]{1,2000})""",
     """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
     """\sstart=({time}\w+\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
     """\suser=(({domain}[^=\\]{1,2000})\\+)?({user}[^=\s]{1,2000})""",
     """userPrincipalName=(({user_email}[^\s=@]{1,2000}@[^@\s=]{1,2000})|({user}[^\s=]{1,2000}))""",
     """userMail=({user_email}[^\s=@]{1,2000}@[^@\s=]{1,2000})""",
     """suid=({user_sid}[^\s]{1,2000})"""
  ]
}
```