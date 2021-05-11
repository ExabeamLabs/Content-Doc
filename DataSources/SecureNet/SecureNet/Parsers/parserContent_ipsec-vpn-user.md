#### Parser Content
```Java
{
Name = ipsec-vpn-user
  Vendor = SecureNet
  Product = SecureNet
  Lms = Direct
  DataType = "vpn-user"
  TimeFormat = "yyyy:MM:dd-HH:mm:ss"
  Conditions = [ """pppd-l2tp[""", """sub="vpn"""", """username=""""  ]
  Fields = [
    """({time}\d\d\d\d:\d\d:\d\d\-\d\d:\d\d:\d\d)\s{1,100}({host}[^\s]+)""",
    """\Wid="({event_code}\d{1,100})""",
    """\Wevent="({event_name}[^"]+)"""",
    """\Wusername="({user}[^"]+)"""",
    """\Wsrcip="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """\Wvirtual_ip="({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""""
  ]
  DupFields = ["user->account"]
}
```