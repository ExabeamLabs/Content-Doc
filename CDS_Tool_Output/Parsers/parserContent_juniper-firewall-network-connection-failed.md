#### Parser Content
```Java
{
Name = juniper-firewall-network-connection-failed
  Conditions = [ """NetScreen""", """ start_time="""", """ src zone=""", """ action=Deny""" ]
  Fields = ${JuniperParserTemplates.juniper-firewall-network-connection.Fields} [
    """\Wreason=({failure_reason}.+?)\s+(\w+=|$)""",
  ]
}

${JuniperParserTemplates.cef-netscreen-network-connection}{
  Name = cef-netscreen-network-connection-permit
  Conditions = [ """CEF:""", """|NetScreen Traffic Permit|""" ]
}
```