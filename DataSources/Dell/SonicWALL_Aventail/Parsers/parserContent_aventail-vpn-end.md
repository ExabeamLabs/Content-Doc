#### Parser Content
```Java
{
Name = aventail-vpn-end
  Vendor = Dell
  Product = SonicWALL Aventail
  Lms = Splunk
  DataType = "vpn-end"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss"
  Conditions = [ """Info System Session End:""",]
  Fields = [
    """exabeam_raw=.*?\[({time}\d\d\/\w+\/\d\d\d\d:\d{1,100}:\d{1,100}:\d{1,100})""",
    """:\s.+?\]\s{1,100}({host}[^\s]{1,2000}).+?\sEnd:.+?\(({user}[^\)]{1,2000})"""
  ]
}
```