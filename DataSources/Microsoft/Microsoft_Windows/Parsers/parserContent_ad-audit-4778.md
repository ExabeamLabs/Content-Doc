#### Parser Content
```Java
{
Name = ad-audit-4778
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4778"
  TimeFormat = "epoch_sec"
  Conditions = [  """4778""", """[ REMARKS = A session was reconnected to a Window Station""", """[ SOURCE = """, """[ USERNAME =""" ]
  Fields = [
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]+) ADACategory""",
    """({host}[\w\-.]+) ADAuditPlus""",
    """USERNAME\s{0,100}=\s{0,100}({user}[^\s\]]+)""",
    """DOMAIN\s{0,100}=\s{0,100}({domain}[^\s\]]+)""",
    """CLIENT_HOST_NAME\s{0,100}=\s{0,100}({dest_host}[^\]]+?)\s{0,100}\]""",
    """SOURCE\s{0,100}=\s{0,100}({src_host}[\w\-.]+)""",
    """RECORD_NUMBER\s{0,100}=\s{0,100}({record_id}\d{1,100})""",
    """({event_code}4778)""",
    """USER_SID\s{0,100}=\s{0,100}(null|({user_sid}[^\s]+))""",
    """LOGON_ID\s{0,100}=\s{0,100}({logon_id}[^\s]+)""",
    """REMARKS\s{0,100}=\s{0,100}({event_name}[^.\]]+)(\.)?\s{1,100}\]""",
    """CLIENT_IP_ADDRESS\s{0,100}=\s{0,100}(null|-|({src_ip}[a-fA-F:\d.]+))"""
  ]
}
```