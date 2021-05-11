#### Parser Content
```Java
{
Name = ad-audit-4779
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4779"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4779""", """A session was disconnected from a Window Station""" ]
  Fields = [
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]+) ADAuditPlus""",
    """USERNAME\s{0,100}=\s{0,100}({user}[^\s\]]+)""",
    """DOMAIN\s{0,100}=\s{0,100}({domain}[^\s\]]+)""",
    """CLIENT_IP_ADDRESS\s{0,100}=\s{0,100}(LOCAL|({dest_ip}[A-Fa-f:\d.]+))""",
    """CLIENT_HOST_NAME\s{0,100}=\s{0,100}(Unknown|({dest_host}[\w\-.]+))""",
    """SOURCE\s{0,100}=\s{0,100}({src_host}[\w\-.]+)""",
    """RECORD_NUMBER\s{0,100}=\s{0,100}({record_id}\d{1,100})""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """LOGON_ID\s{0,100}=\s{0,100}({logon_id}[^\s]+)""",
  ]
}
```