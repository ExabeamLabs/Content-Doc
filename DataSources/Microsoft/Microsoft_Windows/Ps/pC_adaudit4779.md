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
    """({host}[\w\-.]{1,2000}) ADAuditPlus""",
    """USERNAME\s{0,100}=\s{0,100}({user}[^\s\]]{1,2000})""",
    """DOMAIN\s{0,100}=\s{0,100}({domain}[^\s\]]{1,2000})""",
    """CLIENT_IP_ADDRESS\s{0,100}=\s{0,100}(LOCAL|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """CLIENT_HOST_NAME\s{0,100}=\s{0,100}(Unknown|({dest_host}[\w\-.]{1,2000}))""",
    """SOURCE\s{0,100}=\s{0,100}({src_host}[\w\-.]{1,2000})""",
    """RECORD_NUMBER\s{0,100}=\s{0,100}({record_id}\d{1,100})""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """LOGON_ID\s{0,100}=\s{0,100}({logon_id}[^\s]{1,2000})""",
  ]


}
```