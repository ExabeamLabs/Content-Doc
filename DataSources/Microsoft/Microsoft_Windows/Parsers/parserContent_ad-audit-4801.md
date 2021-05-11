#### Parser Content
```Java
{
Name = ad-audit-4801
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4801"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4801""", """REMARKS = The workstation was unlocked.""" ]
  Fields = [
    """({host}[\w\-.]+)\s{1,100}ADAuditPlus""",
    """\WTIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """\WREMARKS\s{0,100}=\s{0,100}({event_name}[^\]]+?)\s{0,100}\]""",
    """\WEVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """\WEVENT_TYPE_TEXT\s{0,100}=\s{0,100}(null|-|({outcome}[^\]]+?))\s{0,100}\]""",
    """\WSOURCE\s{0,100}=\s{0,100}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[\w\-.]+))""",
    """\WLOGON_ID\s{0,100}=\s{0,100}(null|-|({logon_id}[^\]]+?))\s{0,100}\]""",
    """\WDOMAIN\s{0,100}=\s{0,100}(null|-|({domain}[^\s\]]+?))\s{0,100}\]""",
    """\WCALLER_PROCESS_NAME\s{0,100}=\s{0,100}(|null|-|({process}({directory}(\w:)?(?:[^:\]]+)?[\\\/])?({process_name}[^\\\/"\]]+?)))\s{0,100}\]""",
    """\WCLIENT_HOST_NAME\s{0,100}=\s{0,100}(null|({dest_host}[\w\-.]+))""",
    """\WCLIENT_IP_ADDRESS\s{0,100}=\s{0,100}(null|({dest_ip}[A-Fa-f:\d.]+))""",
    """\WUSERNAME\s{0,100}=\s{0,100}(null|-|({user}[^\]\s]+?))\s{0,100}\]""",
    """\WRECORD_NUMBER\s{0,100}=\s{0,100}(null|({record_id}\d{1,100}))""",
    """\WUSER_SID\s{0,100}=\s{0,100}\%?\{?(null|-|({user_sid}[^\s\]\}]+))""",
    """\WFORMAT_MESSAGE\s{0,100}=\s{0,100}(null|-|({additional_info}.+?))\s{0,100}\]""",
    """\WERROR_CODE\s{0,100}=\s{0,100}(null|-|({result_code}[^\s\]]+))""",
    """\WLOGON_TYPE\s{0,100}=\s{0,100}({logon_type}\d{1,100})""",
    """\WLOGON_PROCESS\s{0,100}=\s{0,100}(null|-|({auth_process}[^\s]+))""",
    """\WAUTHENTICATION_PACKAGE\s{0,100}=\s{0,100}(null|-|({auth_package}[^\s]+))""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```