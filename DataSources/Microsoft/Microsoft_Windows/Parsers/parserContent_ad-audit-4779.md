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
    """TIME_GENERATED\s*=\s*({time}\d+)""",
    """({host}[\w\-.]+) ADAuditPlus""",
    """USERNAME\s*=\s*({user}[^\s\]]+)""",
    """DOMAIN\s*=\s*({domain}[^\s\]]+)""",
    """CLIENT_IP_ADDRESS\s*=\s*(LOCAL|({dest_ip}[A-Fa-f:\d.]+))""",
    """CLIENT_HOST_NAME\s*=\s*(Unknown|({dest_host}[\w\-.]+))""",
    """SOURCE\s*=\s*({src_host}[\w\-.]+)""",
    """RECORD_NUMBER\s*=\s*({record_id}\d+)""",
    """EVENT_NUMBER\s*=\s*({event_code}\d+)""",
    """LOGON_ID\s*=\s*({logon_id}[^\s]+)""",
  ]
}
```