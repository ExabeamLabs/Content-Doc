#### Parser Content
```Java
{
Name = cisco-ftd-firewall-5
  DataType = "network-error"
  Conditions = [ """%FTD""", """regular translation creation failed for icmp""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields}[
    """({event_name}regular translation creation failed for icmp)""",
    """src INSIDE:({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\sdst outside:({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""
  ]
}
```