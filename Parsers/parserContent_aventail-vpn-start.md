#### Parser Content
```Java
{
Name = aventail-vpn-start
  Vendor = Dell
  Product = SonicWALL Aventail
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss"
  Conditions = [ """matched rule #""", """is permitted""", """CSACL""" ]
  Fields = [
    """exabeam_raw=.*?\[({time}\d\d\/\w+\/\d\d\d\d:\d+:\d+:\d+)""",
    """:\s.+?\]\s+({host}[^\s]+).+?\sUser.+?\(({user}[^\)]+).+connecting from.+?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):.+access to.+?({dest_host}[\w.-]+)"""
  ]
}
```