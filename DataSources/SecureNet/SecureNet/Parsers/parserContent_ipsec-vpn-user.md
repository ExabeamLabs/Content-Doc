#### Parser Content
```Java
{
Name = ipsec-vpn-user
  Vendor = SecureNet
  Lms = Direct
  DataType = "vpn-user"
  TimeFormat = "yyyy:MM:dd-HH:mm:ss"
  Conditions = [ """pppd-l2tp[""", """sub="vpn"""", """username=""""  ]
  Fields = [
    """({time}\d\d\d\d:\d\d:\d\d\-\d\d:\d\d:\d\d)\s+({host}[^\s]+)""",
    """\Wid="({event_code}\d+)""",
    """\Wevent="({event_name}[^"]+)"""",
    """\Wusername="({user}[^"]+)"""",
    """\Wsrcip="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """\Wvirtual_ip="({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""""
  ]
  DupFields = ["user->account"]
}
```