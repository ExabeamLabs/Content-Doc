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
    """TIME_GENERATED\s*=\s*({time}\d+)""",
    """({host}[\w\-.]+) ADACategory""",
    """({host}[\w\-.]+) ADAuditPlus""",
    """USERNAME\s*=\s*({user}[^\s\]]+)""",
    """DOMAIN\s*=\s*({domain}[^\s\]]+)""",
    """CLIENT_HOST_NAME\s*=\s*({dest_host}[^\]]+?)\s*\]""",
    """SOURCE\s*=\s*({src_host}[\w\-.]+)""",
    """RECORD_NUMBER\s*=\s*({record_id}\d+)""",
    """({event_code}4778)""",
    """USER_SID\s*=\s*(null|({user_sid}[^\s]+))""",
    """LOGON_ID\s*=\s*({logon_id}[^\s]+)""",
    """REMARKS\s*=\s*({event_name}[^.\]]+)(\.)?\s+\]""",
    """CLIENT_IP_ADDRESS\s*=\s*(null|-|({src_ip}[a-fA-F:\d.]+))"""
  ]
}
```