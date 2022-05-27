#### Parser Content
```Java
{
Name = s-infoblox-dhcp-4
  Vendor = Infoblox
  Product = BloxOne
  Lms = Splunk
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ dhcpd[""", """ BOOTREQUEST from """, """BOOTP from dynamic client and no dynamic leases""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s{1,100}({host}[\w.-]{1,2000})\s{1,100}({src_ip}[A-Fa-f\d:.]{1,2000})\s{1,100}dhcpd\[""",
    """\sdhcpd\[\d{1,100}\]:\s{1,100}BOOTREQUEST from ({dest_mac}\S+) via ({dest_ip}[A-Fa-f:\d.]{1,2000}?):?\s"""
  ] 


}
```