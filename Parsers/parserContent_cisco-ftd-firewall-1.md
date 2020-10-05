#### Parser Content
```Java
{
Name = cisco-ftd-firewall-1
  DataType = "network-connection"
  Conditions = [ """%FTD""", """Duplicate TCP SYN""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields} [
  """({event_name}Duplicate TCP SYN)"""
  ]
}
```