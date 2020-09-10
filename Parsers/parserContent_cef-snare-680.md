#### Parser Content
```Java
{
Name = cef-snare-680
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = NitroCefSyslog
  DataType = "windows-680"
  TimeFormat = "epoch"
  Conditions = [ "|Snare|", "|Security:680|"]
  Fields = [ 
    """({event_code}680)""",
    """({event_name}Logon attempt)""",
    """\srt=({time}\d+)""",
    """ahost=({host}[^\s]+)""",
    """suser=({user}.+?)\s+\w+=""",
    """dhost=({dest_host}.+?)\s+\w+="""
  ]
}
```