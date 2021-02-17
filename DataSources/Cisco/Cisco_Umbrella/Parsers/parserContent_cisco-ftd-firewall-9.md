#### Parser Content
```Java
{
Name = cisco-ftd-firewall-9
  DataType = "network-connection"
  Conditions = [ """%FTD-6-805001""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields}[
  """(FTD-6-805001:\s({event_name}.+connection))"""
  ]
}
```