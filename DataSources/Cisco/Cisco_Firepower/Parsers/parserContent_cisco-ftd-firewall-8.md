#### Parser Content
```Java
{
Name = cisco-ftd-firewall-8
  DataType = "vpn-end"
  Conditions = [ """%FTD-6-602304""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields}[
  """(FTD-6-602303: IPSEC:\s({event_name}.+)SA)"""
  ]
}
cisco-ftd-event-1 = {
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[^\s]+)\s{1,20}:\s{1,20}%FTD""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """from ({src_interface}\w+):({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\/*({src_port}\d{0,100})""",
    """to ({dest_interface}\w+):({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\/*(?:({dest_port}\d{1,100}))?""",
    """between ({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}) and ({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""
    ]

```