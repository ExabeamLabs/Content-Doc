#### Parser Content
```Java
{
Name = unix-account-lockout
  DataType = "account-lockout"
  Conditions = [ """[][][""", """ pam_faillock(sshd:auth): User unknown: """ ]
  Fields = ${UnixParserTemplates.unix-events.Fields}[
    """\sUser unknown:\s*(({domain}[^\\]+?)\\+)?({user}[^\\]+?)\s*$""",
    """({auth_method}pam_faillock)"""
  ]
}

${UnixParserTemplates.unix-events}{
  Name = unix-account-keyinit
  DataType = "unix-account-switch"
  Conditions = [ """[][][""", """ pam_keyinit(sudo""" ]
  Fields = ${UnixParserTemplates.unix-events.Fields}[
    """\sUser unknown:\s*(({domain}[^\\]+?)\\+)?({user}[^\\]+)\s*$""",
    """pam_keyinit\S*?:\s*({event_name}.*?change UID to ({account_used_id}\d+).*?)\s*$"""
  ]
}

${UnixParserTemplates.unix-events}{
  Name = unix-auth-failed-2
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