#### Parser Content
```Java
{
Name = n-forwarded-cef-aventail-vpn-end
  Vendor = Dell Aventail
  Product = Aventail
  Lms = NitroCefSyslog
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "Aventail Session End"]
  Fields = [
    """\srt=({time}\d+)""",
    """shost=({host}[^\s]+)""",
    """nitroSource_UserID=({user}[^\r\n]+?)(\s+\w+=|\s*$)""",
    """suser=({user}[^\r\n]+?)(\s+\w+=|\s*$)"""
  ]
}
```