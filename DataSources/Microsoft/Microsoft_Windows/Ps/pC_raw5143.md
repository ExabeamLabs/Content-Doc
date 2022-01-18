#### Parser Content
```Java
{
Name = raw-5143
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "share-access"
  TimeFormat = "EEE MMM dd HH:mm:ss yyyy"
  Conditions = [ """5143""", """A network share object was modified.""", """MSWinEventLog""", """Microsoft-Windows-Security-Auditing""" ]
  Fields = [
    """({time}\w+\s{1,100}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,20}\d{1,100})\s{1,100}({event_code}\d{1,100})\s{1,100}Microsoft-Windows-Security-Auditing""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}MSWinEventLog""",
    """Microsoft-Windows-Security-Auditing\s{1,100}\S+\s{1,100}\S+\s{1,100}({outcome}[^\s]{1,2000}\sAudit)""",
    """({event_name}A network share object was modified)""",
    """Subject:\s{1,100}Security ID:\s{1,100}({user_sid}[^\s]{1,2000})""",
    """Account Name:\s{1,100}({user}[^\s]{1,2000})""",
    """Account Domain:\s{1,100}({domain}[^\s]{1,2000})""",
    """Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """Share Information:\s{1,100}Object Type:\s{1,100}({file_type}[^:]{1,2000}?)\s{1,100}Share Name:""",
    """Share Name:\s{1,100}[\\\*]{0,2000}({share_name}[^\s]{1,2000})\s{1,100}Share Path:""",
    """Share Path:\s{0,100}[\\\?]{0,2000}({share_path}(({d_parent}[^@]{1,2000}?)\\)?(|({d_name}[^\\]{1,2000}?)))\s{0,100}Old Remark:"""
  ]


}
```