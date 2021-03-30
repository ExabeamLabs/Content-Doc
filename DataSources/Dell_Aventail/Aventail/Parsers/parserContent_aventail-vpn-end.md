#### Parser Content
```Java
{
Name = aventail-vpn-end
  Vendor = Dell Aventail
  Product = Aventail
  Lms = Splunk
  DataType = "vpn-end"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss"
  Conditions = [ """Info System Session End:""",]
  Fields = [
    """exabeam_raw=.*?\[({time}\d\d\/\w+\/\d\d\d\d:\d+:\d+:\d+)""",
    """:\s.+?\]\s+({host}[^\s]+).+?\sEnd:.+?\(({user}[^\)]+)"""
  ]
}
```