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
    """\srt=({time}\d+)""",
    """exabeam_host=({host}[^\s]+)""",
    """sntdom=({dest_host}[^\s]+)""",
    """\ssrc=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
  DupFields = [ "dest_host->user" ]
}
```