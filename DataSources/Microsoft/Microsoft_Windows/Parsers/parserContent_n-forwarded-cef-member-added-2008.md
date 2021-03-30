#### Parser Content
```Java
{
Name = n-forwarded-cef-member-added-2008
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = NitroCefSyslog
  DataType = "windows-member-added"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "A member was added to a security-enabled" ]
  Fields = [
    """({event_name}A member was added to a security-enabled [\w\s]+ group)""",
    """\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
    """\srt=({time}\d+)""",
    """shost=({host}[^\s]+)""",
    """A member was added to a security-enabled ({group_type}\w+) group""",
    """sntdom=({domain}[^\s]+)""",
    """suser=({user}.+?)\s+\w+=""",
    """duser=({account_dn}.+?)\s+\w+=""",
    """nitroObjectID=({group_name}.+?)\s+\w+=""",
    """nitroSecurity_ID=({account_id}[^\s]+)""",
    """nitroSource_Logon_ID=({logon_id}.+?)(\s|0\|)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```