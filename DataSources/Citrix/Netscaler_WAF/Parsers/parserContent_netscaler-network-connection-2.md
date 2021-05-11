#### Parser Content
```Java
{
Name = netscaler-network-connection-2
  Vendor = Citrix
  Product = Netscaler WAF
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss z"
  Conditions = [ """ : default""", """ Source """, """ Destination """, """Total_bytes_send""", """Total_bytes_recv""", """-PPE"""]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d\s{0,100}GMT)\s({host}[^\s]+).*?:\sdefault\s({protocol}[^\s]+)\s({event_name}[^\s]+)""",
    """Source\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({src_port}\d{1,100})""",
    """Destination\s({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_port}\d{1,100})""",
    """Total_bytes_send\s({bytes_out}\d{1,100})""",
    """Total_bytes_recv\s({bytes_in}\d{1,100})""",
  ]
  DupFields = ["event_name->activity"]
}
```