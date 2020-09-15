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
${WinParserTemplates.s-xml-windows-member} {
  Name = s-xml-windows-member-14
  DataType = "vpn-end"
  Conditions = [ """<EventID>4304</EventID>""", """<EventRecordID>""" ]
  Fields =${WinParserTemplates.s-xml-windows-member.Fields}[
    """'RemoteIP'>({src_translated_ip}[A-Fa-f:\d.]+)""",
    """'TunnelSourceIP'>({src_ip}[A-Fa-f:\d.]+)""", 
  ]

}
${WinParserTemplates.s-xml-windows-member} {
  Name = s-xml-windows-member-15
  DataType = "config-change"
  Conditions = [ """<EventID>4742</EventID>""", """<EventRecordID>""" ]
}
${WinParserTemplates.s-xml-windows-member} {
  Name = s-xml-windows-member-16
  DataType = "config-change"
  Conditions = [ """<EventID>4957</EventID>""", """<EventRecordID>""" ]
}



{
  Name = metricbeat-5156
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-network"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """"event_id":"5156"""", """"network_information-DestinationAddress"""" ]
  Fields = [
    """({event_name}The Windows Filtering Platform has permitted a connection)""",
    """"host":"({host}[^"]+)"""",
    """"computer":"({host}[^"]+)"""",
    """"event_id":"({event_code}\d+)""",
    """"time":"({time}\d+\/\d+\/\d\d\d\d \d+:\d+:\d+ (AM|PM|am|pm))""",
    """"message":"({event_name}[^"]+)"""",
    """"network_information-SourceAddress":"({dest_ip}[^"]+)".+?"network_information-Direction":"({direction}Inbound)".+?"network_information-SourcePort":"({dest_port}\d+)".+?"network_information-DestinationPort":"({src_port}\d+)".+?"computer":"({dest_host}[^"]+)".+?"network_information-DestinationAddress":"({src_ip}[^"]+)"""",
    """"network_information-SourceAddress":"({src_ip}[^"]+)".+?"network_information-Direction":"({direction}Outbound)".+?"network_information-SourcePort":"({src_port}\d+)".+?"network_information-DestinationPort":"({dest_port}\d+)".+?"computer":"({src_host}[^"]+)".+?"network_information-DestinationAddress":"({dest_ip}[^"]+)"""",
    """"network_information-Protocol":"({protocol_id}[^"]+)"""",
    """"application_information-ProcessID":"({pid}\d+)""",
    """"application_information-ApplicationName":"({process}({directory}.+)[\\\/]({process_name}.+?))"""",
    """"category":"({category}[^"]+)"""",
    """"filter_information-LayerName":"({layer_name}[^"]+)"""",
  ]
  DupFields = ["directory->process_directory"]
}
```