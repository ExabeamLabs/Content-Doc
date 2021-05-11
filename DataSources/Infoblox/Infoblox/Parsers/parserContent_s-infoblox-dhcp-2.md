#### Parser Content
```Java
{
Name = s-infoblox-dhcp-2
  Vendor = Infoblox
  Product = Infoblox
  Lms = Splunk
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " dhcpd[", ": DHCPOFFER " ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({host}\S+) dhcpd\[""",
    """: ({event_name}DHCPOFFER) on ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) to ({dest_mac}[^\s]+)( \(({dest_host}[\w\-.]+)\))?\s{1,100}via ({dest_interface}[^\s]+)""",
  ]
  DupFields = [ "dest_host->user" ]
}
```