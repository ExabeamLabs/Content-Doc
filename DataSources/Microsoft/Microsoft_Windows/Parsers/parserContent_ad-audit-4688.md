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
    """({host}[\w\-.]+)\s{1,100}ADAuditPlus""",
    """\WTIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """\WREMARKS\s{0,100}=\s{0,100}({event_name}[^\]]+?)\s{0,100}\]""",
    """\WEVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """\WEVENT_TYPE_TEXT\s{0,100}=\s{0,100}(null|({outcome}[^\]]+?))\s{0,100}\]""",
    """\WSOURCE\s{0,100}=\s{0,100}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[\w\-.]+))""",
    """\WFILE_NAME\s{0,100}=\s{0,100}(null|({file_name}[^\\\/]+?(\.({file_ext}[^\.]+?))?))\s{0,100}\]""",
    """\WCALLER_LOGON_ID\s{0,100}=\s{0,100}(null|({logon_id}[^\]]+?))\s{0,100}\]""",
    """\WCALLER_USER_DOMAIN\s{0,100}=\s{0,100}(null|({domain}[^\s\]]+?))\s{0,100}\]""",
    """\WPROCESS_NAME\s{0,100}=\s{0,100}(|null|({process}({directory}(\w:)?(?:[^:\]]+)?[\\\/])?({process_name}[^\\\/"\]]+?)))\s{0,100}\]""",
    """\WCALLER_USER_NAME\s{0,100}=\s{0,100}(null|({user}[^\]\s]+?))\s{0,100}\]""",
    """\WRECORD_NUMBER\s{0,100}=\s{0,100}(null|({record_id}\d{1,100}))""",
    """\WCALLER_USER_SID\s{0,100}=\s{0,100}(null|({user_sid}[^\s\]]+))""",
    """\WFORMAT_MESSAGE\s{0,100}=\s{0,100}(null|({additional_info}.+?))\s{0,100}\]""",
    """\WACCOUNT_NAME\s{0,100}=\s{0,100}(null|({caller_user}[^\s]+))""",
    """\WACCOUNT_DOMAIN\s{0,100}=\s{0,100}(null|({caller_domain}[^\s]+))""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```