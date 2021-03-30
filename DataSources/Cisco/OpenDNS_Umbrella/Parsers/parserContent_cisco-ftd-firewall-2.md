#### Parser Content
```Java
{
Name = cisco-ftd-firewall-2
  DataType = "network-connection"
  Conditions = [ """%FTD-6-805002""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields}[
  """(FTD-6-805002:\s({event_name}.+connection))"""
  ]
}
cisco-ftd-event-1 = {
  Vendor = Cisco 
  Product = Cisco Fire Power Devices
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """from ({src_interface}\w+):({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\/*({src_port}\d*)""",
    """to ({dest_interface}\w+):({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\/*(?:({dest_port}\d+))?""",
    """between ({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}) and ({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""
    ]

```