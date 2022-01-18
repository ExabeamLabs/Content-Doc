#### Parser Content
```Java
{
Name = ad-audit-4767
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-unlocked"
  TimeFormat = "epoch_sec"
  Conditions = [ """ADAuditPlus""", """EVENT_NUMBER = 4767""", """REMARKS = A user account was unlocked.""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """({host}[\w\-.]{1,2000})\s{1,100}ADAuditPlus""",
    """\WTIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """\WREMARKS\s{0,100}=\s{0,100}({event_name}[^\]]{1,2000}?)\s{0,100}\]""",
    """\WEVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """\WEVENT_TYPE_TEXT\s{0,100}=\s{0,100}(null|({outcome}[^\]]{1,2000}?))\s{0,100}\]""",
    """\WSOURCE\s{0,100}=\s{0,100}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[\w\-.]{1,2000}))""",
    """\WCALLER_LOGON_ID\s{0,100}=\s{0,100}(null|({logon_id}[^\]]{1,2000}?))\s{0,100}\]""",
    """\WCALLER_USER_DOMAIN\s{0,100}=\s{0,100}(null|({domain}[^\s\]]{1,2000}?))\s{0,100}\]""",
    """\WPROCESS_NAME\s{0,100}=\s{0,100}(|null|({process}({directory}(\w:)?(?:[^:\]]{1,2000})?[\\\/])?({process_name}[^\\\/"\]]{1,2000}?)))\s{0,100}\]""",
    """\WCALLER_USER_NAME\s{0,100}=\s{0,100}(null|({user}[^\]\s]{1,2000}?))\s{0,100}\]""",
    """\WRECORD_NUMBER\s{0,100}=\s{0,100}(null|({record_id}\d{1,100}))""",
    """\WCALLER_USER_SID\s{0,100}=\s{0,100}(null|({user_sid}[^\s\]]{1,2000}))""",
    """\WFORMAT_MESSAGE\s{0,100}=\s{0,100}(null|({additional_info}.+?))\s{0,100}\]""",
    """\WACCOUNT_NAME\s{0,100}=\s{0,100}(null|({caller_user}[^\s]{1,2000}))""",
    """\WACCOUNT_DOMAIN\s{0,100}=\s{0,100}(null|({caller_domain}[^\s]{1,2000}))""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]


}
```