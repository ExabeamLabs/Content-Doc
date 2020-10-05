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
```