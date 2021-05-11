#### Parser Content
```Java
{
Name = cisco-meraki-vpn-start
    Vendor = Cisco
    Product = Cisco Meraki MX appliances
    Lms = Direct
    DataType = "vpn-start"
    TimeFormat = "epoch_sec"
    Conditions = [ " events client_vpn_connect" , "connected from " ]
    Fields = [
      """exabeam_host=({host}[^\s]+)""",
      """({time}\d{10})\.\d{9} \S+\s{1,100}events\s""",
      """client_vpn_connect user id \'({user}[^']+)\'""",
      """local ip ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """connected from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
   ]
  }
```