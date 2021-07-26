#### Parser Content
```Java
{
Name = netscaler-network-connection-3
  Vendor = Citrix
  Product = Netscaler WAF
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss z"
  Conditions = [ """ : default""", """ Backend """, """ ServerIP """, """-PPE"""]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d\s{0,100}GMT)\s({host}[^\s]{1,2000}).*?:\sdefault\s({protocol}[^\s]{1,2000})\s({event_name}[^\s]{1,2000})""",
    """ServerIP\s{0,100}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """ServerPort\s{0,100}({src_port}\d{1,100})""",
    """({outcome}SERVER AUTHENTICATED)""",
  ]
  DupFields = ["event_name->activity"]
}
```