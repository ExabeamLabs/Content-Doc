#### Parser Content
```Java
{
Name = juniper-nwc-vpn-end
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Splunk
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "Juniper:", "NWC23465", "Session ended" ]
  Fields = [
    """({host}[\w\-\.]+)\s*Juniper:""",
    """\stime="+({time}\d+-\d+-\d+ \d+:\d+:\d+).+?user""",
    """user=([^\\]+\\)?({user}.+?)\s+realm""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
    """with IP(v4 address)?\s+({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```