#### Parser Content
```Java
{
Name = ad-audit-4743
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "account-deleted"
  TimeFormat = "epoch_sec"
  Conditions = [ """ [ EVENT_NUMBER = 4743 ] """, """ ADAuditPlus: """, """ [ SOURCE = """, """ [ FORMAT_MESSAGE = """ ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]{1,2000}) ADAuditPlus""",
    """CLIENT_USER_NAME\s{0,100}=\s{0,100}(null|-|SYSTEM|({user}[^\s\]]{1,2000}))\s{0,100}\]""",
    """CLIENT_USER_DOMAIN\s{0,100}=\s{0,100}(null|-|NT AUTHORITY|({domain}[^\s\]]{1,2000}))\s{0,100}\]""",
    """CALLER_USER_NAME\s{0,100}=\s{0,100}(null|-|SYSTEM|({user}[^\s\]]{1,2000}))\s{0,100}\]""",
    """CALLER_USER_DOMAIN\s{0,100}=\s{0,100}(null|-|NT AUTHORITY|({domain}[^\s\]]{1,2000}))\s{0,100}\]""",
    """SOURCE\s{0,100}=\s{0,100}({src_host}[\w\-.]{1,2000})""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """CALLER_USER_SID\s{0,100}=\s{0,100}\%?\{?({user_sid}[^\s\}]{1,2000})""",
    """CALLER_LOGON_ID\s{0,100}=\s{0,100}(null|-|({logon_id}[^\s]{1,2000}))""",
    """ACCOUNT_NAME\s{0,100}=\s{0,100}(null|-|({object}[^\s]{1,2000}))""",
    """REMARKS\s{0,100}=\s{0,100}(null|-|({event_name}[^.\]]{1,2000}))(\.)?\s{1,100}\]""",
    """FORMAT_MESSAGE\s{0,100}=\s{0,100}(null|-|({additional_info}[^.\]]{1,2000}))(\.)?\s{1,100}\]""",
    """Category\s{0,100}=\s{0,100}({category}[^\s]{1,2000})"""
 ]
  DupFields = [ "host->dest_host" ]


}
```