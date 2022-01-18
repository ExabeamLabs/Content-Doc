#### Parser Content
```Java
{
Name = n-forwarded-cef-infoblox-dhcp
  Vendor = Infoblox
  Product = Infoblox
  Lms = NitroCefSyslog
  DataType = "dhcp"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "Added Forward Map", "dhcpd" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """sntdom=({dest_host}[^\s]{1,2000})""",
    """\ssrc=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
  DupFields = [ "dest_host->user" ]


}
```