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
```