#### Parser Content
```Java
{
Name = s-4740-2
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-lockout"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""Account That Was Locked Out""", """ ComputerName=""", """Account Name=""", """ EventID=4740 """]
  Fields = [
    """({event_name}Account That Was Locked Out)""",
    """({event_code}4740)""",
    """\sComputerName=({host}[^\s]+)""",
    """Locked Out:Security ID=({user_sid}[^\s]+)""",
    """\sDetectTime=({time}\d\d\d\d-\d+-\d+ \d+:\d+:\d+)\s""",
    """\sUser=(null|({user}[^\s]+))""",
    """\sEventType=({outcome}[^\s]+)""",
    """Caller Computer Name=({src_host}[^\s]+)""",
    """Account Name=({user}[^\s]+)""",
    """Account Domain=({domain}[^\s]+)""",
    """Logon ID=({logon_id}[^\s"]+)""",
    """Security ID=({sid}[^\s]+)""",
  ]
  DupFields=[ "host->dest_host", "domain->caller_domain" ]
}
```