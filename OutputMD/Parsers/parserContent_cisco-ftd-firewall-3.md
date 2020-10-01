#### Parser Content
```Java
{
Name = cisco-ftd-firewall-3
  DataType = "network-connection"
  Conditions = [ """FTD-6-305012""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields}[
  """(FTD-6-305012:\s({event_name}.+translation))"""
  ]
}
```