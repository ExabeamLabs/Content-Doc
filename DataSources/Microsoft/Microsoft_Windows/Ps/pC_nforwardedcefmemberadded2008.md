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
    """({event_name}A member was added to a security-enabled [\w\s]{1,2000} group)""",
    """\|McAfee\|[^|]{1,2000}?\|[^|]{1,2000}?\|43-2630({event_code}\d{1,100})(0|1)\|""",
    """\srt=({time}\d{1,100})""",
    """shost=({host}[^\s]{1,2000})""",
    """A member was added to a security-enabled ({group_type}\w+) group""",
    """sntdom=({domain}[^\s]{1,2000})""",
    """suser=({user}.+?)\s{1,100}\w+=""",
    """duser=({account_dn}.+?)\s{1,100}\w+=""",
    """nitroObjectID=({group_name}.+?)\s{1,100}\w+=""",
    """nitroSecurity_ID=({account_id}[^\s]{1,2000})""",
    """nitroSource_Logon_ID=({logon_id}.+?)(\s|0\|)"""
  ]
  DupFields = [ "host->dest_host" ]


}
```