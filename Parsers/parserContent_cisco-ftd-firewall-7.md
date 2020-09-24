#### Parser Content
```Java
{
Name = cisco-ftd-firewall-7
  DataType = "vpn-start"
  Conditions = [ """%FTD-6-602303""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields}[
  """(FTD-6-602303: IPSEC:\s({event_name}.+)SA)"""
  ]
}
```