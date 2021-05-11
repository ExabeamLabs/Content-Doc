#### Parser Content
```Java
{
Name = n-forwarded-cef-aventail-vpn-end
  Vendor = Dell
  Product = SonicWALL Aventail
  Lms = NitroCefSyslog
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "Aventail Session End"]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """shost=({host}[^\s]+)""",
    """nitroSource_UserID=({user}[^\r\n]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """suser=({user}[^\r\n]+?)(\s{1,100}\w+=|\s{0,100}$)"""
    """deviceTranslatedAddress=({src_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""", 
    """src=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""", 
  ]
  DupFields = ["user->account"]
}
```