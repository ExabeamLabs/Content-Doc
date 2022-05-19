#### Parser Content
```Java
{
Name = unix-ssh-login-failed-2
  Vendor = Unix
  Product = Unix
  Lms = Syslog
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """sshd[""", """[ID """, """ auth.""", """] Failed """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d (::ffff:)?({host}({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|({dest_host}[\w\-.]{1,2000})))\s""",
    """(Failed (none|publickey|keyboard-interactive|password) for (<invalid username>|({user}[^\s]{1,2000})) from ({src_ip}[a-fA-F:\.\d]{1,2000})\sport ({src_port}\d{1,100}) ssh2)""",
    """Failed (none|publickey|keyboard-interactive) for <({failure_reason}[^>]{1,2000})>""",
    """({event_code}ssh)""",
    """({protocol}ssh(d)?)"""
  ]


}
```