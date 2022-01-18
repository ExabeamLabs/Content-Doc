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
    """\|McAfee\|[^|]{1,2000}?\|[^|]{1,2000}?\|43-2630({event_code}\d{1,100})(0|1)\|""",
    """\srt=({time}\d{1,100})(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """shost=({host}[^\s]{1,2000})""",
    """src=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """sntdom=({domain}[^\s]{1,2000})""",
    """suser=({user}[^\s]{1,2000})""",
    """nitroUserIDSrc=({user}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """nitroSecurity_ID=({user_sid}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """nitroSource_Logon_ID=({logon_id}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """nitroObjectID=({object_dn}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """nitroObjectID=.*?({object_ou}(OU|ou).+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """nitroTarget_Class=({object_class}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)"""
]


}
```