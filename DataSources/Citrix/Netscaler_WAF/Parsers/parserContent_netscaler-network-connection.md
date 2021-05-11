#### Parser Content
```Java
{
Name = netscaler-network-connection
  Vendor = Citrix
  Product = Netscaler WAF
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss z"
  Conditions = [ """ : default""", """ Vserver""", """-PPE"""]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d\s{0,100}GMT)\s({host}[^\s]+).*?:\sdefault\s({protocol}[^\s]+)\s({event_name}[^\s]+)""",
    """Source\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({src_port}\d{1,100})""",
    """ClientIP\s{0,100}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """ClientPort\s{0,100}({src_port}\d{1,100})""",
    """Vserver\s({dest_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_translated_port}\d{1,100})""",
    """VserverServiceIP\s({dest_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """VserverServicePort\s{0,100}({dest_translated_port}\d{1,100})""",
    """NatIP\s({src_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({src_translated_port}\d{1,100})""",
    """Destination\s({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_port}\d{1,100})""",
    """Total_bytes_send\s({bytes_out}\d{1,100})""",
    """Total_bytes_recv\s({bytes_in}\d{1,100})""",
  ]
  DupFields = ["event_name->activity"]
}
```