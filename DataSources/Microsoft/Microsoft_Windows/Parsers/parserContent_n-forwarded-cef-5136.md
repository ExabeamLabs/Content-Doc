#### Parser Content
```Java
{
Name = n-forwarded-cef-5136
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = NitroCefSyslog
  DataType = "windows-ds-access"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "43-263051360"]
  Fields = [
    """({event_name}A directory service object was modified.)""",
    """\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
    """\srt=({time}\d+)(\s+\w+=|"*\s*$)""",
    """shost=({host}[^\s]+)""",
    """src=({src_ip}[a-fA-F:\d.]+)""",
    """sntdom=({domain}[^\s]+)""",
    """suser=({user}[^\s]+)""",
    """nitroUserIDSrc=({user}.+?)(\s+\w+=|"*\s*$)""",
    """nitroSecurity_ID=({user_sid}.+?)(\s+\w+=|"*\s*$)""",
    """nitroSource_Logon_ID=({logon_id}.+?)(\s+\w+=|"*\s*$)""",
    """nitroObjectID=({object_dn}.+?)(\s+\w+=|"*\s*$)""",
    """nitroObjectID=.*?({object_ou}(OU|ou).+?)(\s+\w+=|"*\s*$)""",
    """nitroTarget_Class=({object_class}.+?)(\s+\w+=|"*\s*$)"""
]
}
```