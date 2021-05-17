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
    """\srt=({time}\d{1,100})""",
    """ahost=({host}[^\s]{1,2000})""",
    """suser=({user}.+?)\s{1,100}\w+=""",
    """dhost=({dest_host}.+?)\s{1,100}\w+="""
  ]
}
```