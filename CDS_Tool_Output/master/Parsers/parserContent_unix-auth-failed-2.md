#### Parser Content
```Java
{
Name = unix-auth-failed-2
  Product = Unix
  DataType = "authentication-failed"
  Conditions = [ """[][][""", """ pam_unix(sudo""", """ authentication failure""" ]
  Fields = ${UnixParserTemplates.unix-events.Fields}[
    """\sruser=(|({account}.+?))(\s+\w+=|\s*$)""",
    """\suser=(|({user}.+?))(\s+\w+=|\s*$)""",
    """\suid=(|({user_id}.+?))(\s+\w+=|\s*$)""",
  ]
}

{
  Name = unix-failed-logon-7
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "failed-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Disconnecting: Too many authentication failures for""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]+)\s+sshd\[""",
    """({event_name}Too many authentication failures for ({user}\S+))""",
  ]
}
```