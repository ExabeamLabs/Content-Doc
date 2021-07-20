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
    """exabeam_raw=.*?\[({time}\d\d\/\w+\/\d\d\d\d:\d{1,100}:\d{1,100}:\d{1,100})""",
    """:\s.+?\]\s{1,100}({host}[^\s]{1,2000}).+?\sUser.+?\(({user}[^\)]{1,2000}).+connecting from.+?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):.+access to.+?({dest_host}[\w.-]{1,2000})"""
  ]
}
```