#### Parser Content
```Java
{
Name = n-forwarded-cef-aventail-vpn-start
  Vendor = Dell Aventail
  Product = Aventail
  Lms = NitroCefSyslog
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "User Login and zone assignment"]
  Fields = [
    """\srt=({time}\d+)""",
    """shost=({host}[^\s]+)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """nitroSource_UserID=({user}[^\r\n]+?)(\s+\w+=|\s*$)""",
    """suser=({user}[^\r\n]+?)(\s+\w+=|\s*$)""",
  ]
}
```