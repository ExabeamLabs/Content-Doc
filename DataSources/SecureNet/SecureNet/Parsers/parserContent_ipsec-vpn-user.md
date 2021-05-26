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
    """({time}\d\d\d\d:\d\d:\d\d\-\d\d:\d\d:\d\d)\s{1,100}({host}[^\s]{1,2000})""",
    """\Wid="({event_code}\d{1,100})""",
    """\Wevent="({event_name}[^"]{1,2000})"""",
    """\Wusername="({user}[^"]{1,2000})"""",
    """\Wsrcip="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """\Wvirtual_ip="({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""""
  ]
  DupFields = ["user->account"]
}
```