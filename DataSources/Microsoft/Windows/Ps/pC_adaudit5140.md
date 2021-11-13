#### Parser Content
```Java
{
Name = ad-audit-5140
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "share-access"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 5140""", """REMARKS = A network share object was accessed.""" ]
  Fields = [
    """({host}[\w\-.]{1,2000})\s{1,100}ADAuditPlus""",
    """\WTIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """\WREMARKS\s{0,100}=\s{0,100}({event_name}[^\]]{1,2000}?)\s{0,100}\]""",
    """\WEVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """\WEVENT_TYPE_TEXT\s{0,100}=\s{0,100}(null|({outcome}[^\]]{1,2000}?))\s{0,100}\]""",
    """\WSOURCE\s{0,100}=\s{0,100}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[\w\-.]{1,2000}))""",
    """\WOBJECT_NAME\s{0,100}=\s{0,100}(null|({object}[^\]]{1,2000}?))\s{0,100}\]""",
    """\WFILE_NAME\s{0,100}=\s{0,100}(null|({file_name}[^\\\/]{1,2000}?(\.({file_ext}[^\.]{1,2000}?))?))\s{0,100}\]""",
    """\WFILE_LOCATION\s{0,100}=\s{0,100}(null|({file_parent}[^\]]{1,2000}?))\s{0,100}\]""",
    """\WLOGON_ID\s{0,100}=\s{0,100}(null|({logon_id}[^\]]{1,2000}?))\s{0,100}\]""",
    """\WDOMAIN\s{0,100}=\s{0,100}(null|({domain}[^\s\]]{1,2000}?))\s{0,100}\]""",
    """\WPROCESS_NAME\s{0,100}=\s{0,100}(|null|({process}({directory}(\w:)?(?:[^:\]]{1,2000})?[\\\/])?({process_name}[^\\\/"\]]{1,2000}?)))\s{0,100}\]""",
    """\WUSERNAME\s{0,100}=\s{0,100}(null|({user}[^\]\s]{1,2000}?))\s{0,100}\]""",
    """\WRECORD_NUMBER\s{0,100}=\s{0,100}(null|({record_id}\d{1,100}))""",
    """\WUSER_SID\s{0,100}=\s{0,100}(null|({user_sid}[^\s\]]{1,2000}))""",
    """\WFORMAT_MESSAGE\s{0,100}=\s{0,100}(null|({additional_info}.+?))\s{0,100}\]""",
    """\WACCESSES\s{0,100}=\s{0,100}(null|({accesses}[^\]]{1,2000}?))\s{0,100}\]""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "object->file_path" ]


}
```