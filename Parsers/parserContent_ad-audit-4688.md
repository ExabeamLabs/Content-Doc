#### Parser Content
```Java
{
Name = ad-audit-4688
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4688""", """REMARKS = A new process has been created.""" ]
  Fields = [
    """({host}[\w\-.]+)\s+ADAuditPlus""",
    """\WTIME_GENERATED\s*=\s*({time}\d+)""",
    """\WREMARKS\s*=\s*({event_name}[^\]]+?)\s*\]""",
    """\WEVENT_NUMBER\s*=\s*({event_code}\d+)""",
    """\WEVENT_TYPE_TEXT\s*=\s*(null|({outcome}[^\]]+?))\s*\]""",
    """\WSOURCE\s*=\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[\w\-.]+))""",
    """\WFILE_NAME\s*=\s*(null|({file_name}[^\\\/]+?(\.({file_ext}[^\.]+?))?))\s*\]""",
    """\WCALLER_LOGON_ID\s*=\s*(null|({logon_id}[^\]]+?))\s*\]""",
    """\WCALLER_USER_DOMAIN\s*=\s*(null|({domain}[^\s\]]+?))\s*\]""",
    """\WPROCESS_NAME\s*=\s*(|null|({process}({directory}(\w:)?(?:[^:\]]+)?[\\\/])?({process_name}[^\\\/"\]]+?)))\s*\]""",
    """\WCALLER_USER_NAME\s*=\s*(null|({user}[^\]\s]+?))\s*\]""",
    """\WRECORD_NUMBER\s*=\s*(null|({record_id}\d+))""",
    """\WCALLER_USER_SID\s*=\s*(null|({user_sid}[^\s\]]+))""",
    """\WFORMAT_MESSAGE\s*=\s*(null|({additional_info}.+?))\s*\]""",
    """\WACCOUNT_NAME\s*=\s*(null|({caller_user}[^\s]+))""",
    """\WACCOUNT_DOMAIN\s*=\s*(null|({caller_domain}[^\s]+))""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```