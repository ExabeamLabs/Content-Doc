#### Parser Content
```Java
{
Name = ad-audit-4800
  Vendor = AD Audit
  Product = AD Audit
  Lms = Direct
  DataType = "windows-4800"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4800""", """REMARKS = The workstation was locked.""" ]
  Fields = [
    """({host}[\w\-.]+)\s+ADAuditPlus""",
    """\WTIME_GENERATED\s*=\s*({time}\d+)""",
    """\WREMARKS\s*=\s*({event_name}[^\]]+?)\s*\]""",
    """\WEVENT_NUMBER\s*=\s*({event_code}\d+)""",
    """\WEVENT_TYPE_TEXT\s*=\s*(null|-|({outcome}[^\]]+?))\s*\]""",
    """\WSOURCE\s*=\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[\w\-.]+))""",
    """\WLOGON_ID\s*=\s*(null|-|({logon_id}[^\]]+?))\s*\]""",
    """\WDOMAIN\s*=\s*(null|-|({domain}[^\s\]]+?))\s*\]""",
    """\WCALLER_PROCESS_NAME\s*=\s*(null|-||({process}({directory}(\w:)?(?:[^:\]]+)?[\\\/])?({process_name}[^\\\/"\]]+?)))\s*\]""",
    """\WCLIENT_HOST_NAME\s*=\s*(null|({dest_host}[\w\-.]+))""",
    """\WCLIENT_IP_ADDRESS\s*=\s*(null|({dest_ip}[A-Fa-f:\d.]+))""",
    """\WUSERNAME\s*=\s*(null|-|({user}[^\]\s]+?))\s*\]""",
    """\WRECORD_NUMBER\s*=\s*(null|-|({record_id}\d+))""",
    """\WUSER_SID\s*=\s*\%?\{?(null|-|({user_sid}[^\s\]\}]+))""",
    """\WFORMAT_MESSAGE\s*=\s*(null|-|({additional_info}.+?))\s*\]""",
    """\WERROR_CODE\s*=\s*(null|-|({result_code}[^\s\]]+))""",
    """\WLOGON_TYPE\s*=\s*({logon_type}\d+)""",
    """\WLOGON_PROCESS\s*=\s*(null|-|({auth_process}[^\s]+))""",
    """\WAUTHENTICATION_PACKAGE\s*=\s*(null|-|({auth_package}[^\s]+))""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```