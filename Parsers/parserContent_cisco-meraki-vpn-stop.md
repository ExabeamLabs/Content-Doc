#### Parser Content
```Java
{
Name = cisco-meraki-vpn-stop
    Vendor = Cisco
    Product = Cisco Meraki MX appliances
    Lms = Direct
    DataType = "vpn-end"
    TimeFormat = "epoch_sec"
    Conditions = [ " events client_vpn_disconnect" , "connected from " ]
    Fields = [
      """exabeam_host=({host}[^\s]+)""",
      """({time}\d{10})\.\d{9} \S+\s+events\s""",
      """client_vpn_disconnect user id \'({user}[^']+)\'""",
      """local ip ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """connected from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
   ]
  }
```