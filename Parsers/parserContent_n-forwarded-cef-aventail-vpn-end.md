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
    """\srt=({time}\d+)""",
    """shost=({host}[^\s]+)""",
    """nitroSource_UserID=({user}[^\r\n]+?)(\s+\w+=|\s*$)""",
    """suser=({user}[^\r\n]+?)(\s+\w+=|\s*$)"""
    """deviceTranslatedAddress=({src_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""", 
    """src=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""", 
  ]
  DupFields = ["user->account"]
}
```