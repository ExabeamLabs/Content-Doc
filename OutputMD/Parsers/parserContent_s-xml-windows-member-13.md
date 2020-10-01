#### Parser Content
```Java
{
Name = s-xml-windows-member-13
  DataType = "vpn-start"
  Conditions = [ """<EventID>4303</EventID>""" ,"""<EventRecordID>""" ]
   Fields =${WinParserTemplates.s-xml-windows-member.Fields}[
    """'ClientMachineName'>(Unknown|({src_host}[\w\-.]+))""",
    """'RemoteIP'>({src_translated_ip}[A-Fa-f:\d.]+)""",
    """'TunnelSourceIP'>({src_ip}[A-Fa-f:\d.]+)""",

  ]
}
```