#### Parser Content
```Java
{
Name = netscaler-network-connection
  Vendor = Citrix Netscaler
  Product = Netscaler WAF
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss z"
  Conditions = [ """ : default""", """ Vserver""", """-PPE"""]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d\s*GMT)\s({host}[^\s]+).*?:\sdefault\s({protocol}[^\s]+)\s({event_name}[^\s]+)""",
    """Source\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({src_port}\d+)""",
    """ClientIP\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """ClientPort\s*({src_port}\d+)""",
    """Vserver\s({dest_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_translated_port}\d+)""",
    """VserverServiceIP\s({dest_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """VserverServicePort\s*({dest_translated_port}\d+)""",
    """NatIP\s({src_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({src_translated_port}\d+)""",
    """Destination\s({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_port}\d+)""",
    """Total_bytes_send\s({bytes_out}\d+)""",
    """Total_bytes_recv\s({bytes_in}\d+)""",
  ]
  DupFields = ["event_name->activity"]
}
```