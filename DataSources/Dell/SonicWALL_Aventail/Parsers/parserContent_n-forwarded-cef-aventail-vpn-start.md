#### Parser Content
```Java
{
Name = n-forwarded-cef-aventail-vpn-start
  Vendor = Dell
  Product = SonicWALL Aventail
  Lms = NitroCefSyslog
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "User Login and zone assignment"]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """shost=({host}[^\s]{1,2000})""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """nitroSource_UserID=({user}[^\r\n]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """suser=({user}[^\r\n]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """deviceTranslatedAddress=({src_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""", 
    """src=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
  ]
  DupFields = ["user->account"]
}
```