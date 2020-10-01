#### Parser Content
```Java
{
Name = ad-audit-4663
  Vendor = ManageEngine
  Product = AD Audit
  Lms = Direct
  DataType = "windows-4663"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4663""", """REMARKS = An attempt was made to access an object.""" ]
  Fields = [
    """({host}[\w\-.]+)\s+ADAuditPlus""",
    """\WTIME_GENERATED\s*=\s*({time}\d+)""",
    """\WREMARKS\s*=\s*({event_name}[^\]]+?)\s*\]""",
    """\WEVENT_NUMBER\s*=\s*({event_code}\d+)""",
    """\WEVENT_TYPE_TEXT\s*=\s*(null|({outcome}[^\]]+?))\s*\]""",
    """\WSOURCE\s*=\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[\w\-.]+))""",
    """\WOBJECT_NAME\s*=\s*(null|({object}[^\]]+?))\s*\]""",
    """\WFILE_NAME\s*=\s*(null|({file_name}[^\\\/]+?(\.({file_ext}[^\.]+?))?))\s*\]""",
    """\WFILE_LOCATION\s*=\s*(null|({file_parent}[^\]]+?))\s*\]""",
    """\WLOGON_ID\s*=\s*(null|({logon_id}[^\]]+?))\s*\]""",
    """\WDOMAIN\s*=\s*(null|({domain}[^\s\]]+?))\s*\]""",
    """\WPROCESS_NAME\s*=\s*(null||({process}({directory}(\w:)?(?:[^:\]]+)?[\\\/])?({process_name}[^\\\/"\]]+?)))\s*\]""",
    """\WCLIENT_HOST_NAME\s*=\s*(null|({dest_host}[\w\-.]+))""",
    """\WCLIENT_IP_ADDRESS\s*=\s*(null|({dest_ip}[A-Fa-f:\d.]+))""",
    """\WUSERNAME\s*=\s*(null|({user}[^\]\s]+?))\s*\]""",
    """\WRECORD_NUMBER\s*=\s*(null|({record_id}\d+))""",
    """\WUSER_SID\s*=\s*(null|({user_sid}[^\s\]]+))""",
    """\WFORMAT_MESSAGE\s*=\s*(null|({additional_info}.+?))\s*\]""",
    """\WFILE_TYPE\s*=\s*(null|({file_type}[^\]]+?))\s*\]""",
    """\WACCESSES\s*=\s*(null|({accesses}[^\]]+?))\s*\]""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "object->file_path" ]
}
```