#### Parser Content
```Java
{
Name = s-xml-windows-member-14
  DataType = "vpn-end"
  Conditions = [ """<EventID>4304</EventID>""", """<EventRecordID>""" ]
  Fields =${WinParserTemplates.s-xml-windows-member.Fields}[
    """'RemoteIP'>({src_translated_ip}[A-Fa-f:\d.]+)""",
    """'TunnelSourceIP'>({src_ip}[A-Fa-f:\d.]+)""", 
  ]

}
```