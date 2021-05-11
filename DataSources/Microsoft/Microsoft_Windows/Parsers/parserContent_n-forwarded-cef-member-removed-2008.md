#### Parser Content
```Java
{
Name = n-forwarded-cef-member-removed-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = NitroCefSyslog
  DataType = "windows-member-removed"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "A member was removed from a security-enabled" ]
  Fields = [
    """({event_name}A member was removed from a security-enabled [\w\s]+ group)""",
    """\|McAfee\|[^|]+?\|[^|]+?\|43-2630({event_code}\d{1,100})(0|1)\|""",
    """\srt=({time}\d{1,100})""",
    """shost=({host}[^\s]+)""",
    """A member was removed from a security-enabled ({group_type}\w+) group""",
    """sntdom=({domain}[^\s]+)""",
    """suser=({user}.+?)\s{1,100}\w+=""",
    """duser=({sid_user}.+?)\s{1,100}\w+=""",
    """nitroObjectID=({group_name}.+?)\s{1,100}\w+=""",
    """nitroSecurity_ID=({account_id}[^\s]+)""",
    """nitroSource_Logon_ID=({logon_id}.+?)(\s|0\|)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```