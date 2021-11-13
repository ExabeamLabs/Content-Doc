#### Parser Content
```Java
{
Name = sophos-network-connection-2
  Vendor = Sophos
  Product = Sophos Firewall
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "yyyy:MM:dd-HH:mm:ss"
  Conditions = [""" ulogd[""", """ sub=""",""" action=""" ]
  Fields = [
    """({time}\d{1,100}:\d{1,100}:\d{1,100}-\d{1,100}:\d{1,100}:\d{1,100})"""
    """exabeam_host=({host}[^\s]{1,2000})""",
    """ulogd\[({log_id}\d{1,100})""",
    """action="({outcome}[^"]{1,2000})""",
    """fwrule="({rule_id}\d{1,100})""",
    """srcmac="({src_mac}[^"]{1,2000})""",
    """dstmac="({dest_mac}[^"]{1,2000})""",
    """srcip="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """dstip="({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """proto="({protocol}[^"]{1,2000})""",
    """srcport="({src_port}\d{1,100})""",
    """dstport="({dest_port}\d{1,100})""",
    """initf="({src_interface}[^"]{1,2000})""",
    """outitf="({dest_interface}[^"]{1,2000})""",
    """length="({bytes}\d{1,100})""",
    """name="({event_name}[^"]{1,2000})""",
    """severity="({alert_severity}[^"]{1,2000})"""
  ]


}
```