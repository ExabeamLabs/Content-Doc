#### Parser Content
```Java
{
Name = cisco-ftd-firewall-6
  DataType = "network-connection"
  Conditions = [ """FTD-6-305011""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields}[
    """(FTD-6-305011:\s({event_name}.+translation))""",
    ]
}
```