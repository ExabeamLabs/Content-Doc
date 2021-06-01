#### Parser Content
```Java
{
Name = ad-audit-5139
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-ds-access"
  TimeFormat = "epoch_sec"
  Conditions = [ """EVENT_NUMBER = 5139""",""" Account Moved """]
  Fields = [
    """TIME_GENERATED\s{0,100}=\s{0,100}({time}\d{1,100})""",
    """({host}[\w\-.]{1,2000}) ADAuditPlus""",
    """EVENT_NUMBER\s{0,100}=\s{0,100}({event_code}\d{1,100})""",
    """({event_name}User Account Moved)""",
    """CALLER_LOGON_ID\s{0,100}=\s{0,100}({logon_id}[^]]{1,2000}?)\s{0,100}\]""",
    """ACCOUNT_DOMAIN\s{0,100}=\s{0,100}({domain}[^]]{1,2000}?)\s{0,100}\]""",
    """ATTRIBUTES_NEW_VALUE\s{0,100}=\s{0,100}({new_attribute}[^]]{1,2000}?)\s{0,100}\]""",
    """ATTRIBUTES_OLD_VALUE\s{0,100}=\s{0,100}({old_attribute}[^]]{1,2000}?)\s{0,100}\]""",
    """\sCORRELATION_ID\s{0,100}=\s{0,100}(null|({correlation_id}[^]]{1,2000}?))\s{0,100}\]""",
    """ACCOUNT_NAME\s{0,100}=\s{0,100}(({user}[^]]{1,2000}?))\s{0,100}\]""",
    """ACCOUNT_SID\s{0,100}=\s{0,100}(({user_sid}[^]]{1,2000}?))\s{0,100}\]""",	
  ]
  DupFields = [ "host->dest_host"]
}
```