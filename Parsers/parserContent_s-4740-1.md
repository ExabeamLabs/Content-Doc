#### Parser Content
```Java
{
Name = s-4740-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-account-lockout"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """EventCode=4740""", """EventType=""", """A user account was locked out""" ]
  Fields = [
    """({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
    """ComputerName=({dest_host}[\w\-.]+)""",
    """({event_code}4740)""",
    """({event_name}A user account was locked out)"""
    """RecordNumber=({record_id}[^;"]+)""",
    """Keywords=({outcome}[^;"]+)""",
    """Subject=.*?Account Name=({caller_user}[^;"\s]+)""",
    """Subject=.*?Account Domain=({caller_domain}[^;"\s]+)""",
    """Logon ID=({logon_id}[^;"\s]+)""",
    """Security ID=({user_sid}[^;"]+);Account Name=({user}[^;"\s]+);Additional Information=""",
    """Caller Computer Name=\\*({src_host}[\w\-.]+)""",
  ]
  DupFields=[ "caller_domain->domain" ]
}
```