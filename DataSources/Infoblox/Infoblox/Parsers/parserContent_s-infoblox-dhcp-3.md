#### Parser Content
```Java
{
Name = s-infoblox-dhcp-3
  Vendor = Infoblox
  Product = Infoblox
  Lms = Splunk
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ dhcpd[""", """: received a REQUEST DHCP packet from """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """ ({host}\S+) \S+ dhcpd\[""",
    """REQUEST DHCP packet from relay-agent ({dest_interface}\S+) with """,
    """ for ({dest_ip}[A-Fa-f:\d.]{1,2000}) \(({dest_mac}\S+)\)""",
  ]
  DupFields = [ "dest_host->user" ]
}
```