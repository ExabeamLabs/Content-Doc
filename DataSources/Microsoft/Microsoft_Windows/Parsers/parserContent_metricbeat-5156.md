#### Parser Content
```Java
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
    """"event_id":"({event_code}\d{1,100})""",
    """"time":"({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (AM|PM|am|pm))""",
    """"message":"({event_name}[^"]+)"""",
    """"network_information-SourceAddress":"({dest_ip}[^"]+)".+?"network_information-Direction":"({direction}Inbound)".+?"network_information-SourcePort":"({dest_port}\d{1,100})".+?"network_information-DestinationPort":"({src_port}\d{1,100})".+?"computer":"({dest_host}[^"]+)".+?"network_information-DestinationAddress":"({src_ip}[^"]+)"""",
    """"network_information-SourceAddress":"({src_ip}[^"]+)".+?"network_information-Direction":"({direction}Outbound)".+?"network_information-SourcePort":"({src_port}\d{1,100})".+?"network_information-DestinationPort":"({dest_port}\d{1,100})".+?"computer":"({src_host}[^"]+)".+?"network_information-DestinationAddress":"({dest_ip}[^"]+)"""",
    """"network_information-Protocol":"({protocol_id}[^"]+)"""",
    """"application_information-ProcessID":"({pid}\d{1,100})""",
    """"application_information-ApplicationName":"({process}({directory}.+)[\\\/]({process_name}.+?))"""",
    """"category":"({category}[^"]+)"""",
    """"filter_information-LayerName":"({layer_name}[^"]+)"""",
  ]
  DupFields = ["directory->process_directory"]
}
```