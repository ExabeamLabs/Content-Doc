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
```