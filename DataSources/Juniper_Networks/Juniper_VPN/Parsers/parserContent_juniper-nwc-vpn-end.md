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
    """({host}[\w\-\.]{1,2000})\s{0,100}Juniper:""",
    """\stime="{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}).+?user""",
    """user=([^\\]{1,2000}\\)?({user}.+?)\s{1,100}realm""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
    """with IP(v4 address)?\s{1,100}({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```