#### Parser Content
```Java
{
Name = cisco-ftd-firewall-5
  DataType = "network-error"
  Conditions = [ """%FTD""", """regular translation creation failed for icmp""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields}[
    """({event_name}regular translation creation failed for icmp)""",
    """src INSIDE:({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\sdst outside:({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """src\s+({src_interface}.+?):({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\sdst\s+({dest_interface}.+?):({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""
  ]
}
cisco-ftd-event-1 = {
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[^\s]+)\s{1,20}:\s{1,20}%FTD""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """from ({src_interface}\w+):({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\/*({src_port}\d*)""",
    """to ({dest_interface}\w+):({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\/*(?:({dest_port}\d+))?""",
    """between ({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}) and ({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""
    ]

```