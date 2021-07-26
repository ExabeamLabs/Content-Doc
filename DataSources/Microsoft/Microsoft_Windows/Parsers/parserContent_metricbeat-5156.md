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
    """"host":"({host}[^"]{1,2000})"""",
    """"computer":"({host}[^"]{1,2000})"""",
    """"event_id":"({event_code}\d{1,100})""",
    """"time":"({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (AM|PM|am|pm))""",
    """"message":"({event_name}[^"]{1,2000})"""",
    """"network_information-SourceAddress":"({dest_ip}[^"]{1,2000})".+?"network_information-Direction":"({direction}Inbound)".+?"network_information-SourcePort":"({dest_port}\d{1,100})".+?"network_information-DestinationPort":"({src_port}\d{1,100})".+?"computer":"({dest_host}[^"]{1,2000})".+?"network_information-DestinationAddress":"({src_ip}[^"]{1,2000})"""",
    """"network_information-SourceAddress":"({src_ip}[^"]{1,2000})".+?"network_information-Direction":"({direction}Outbound)".+?"network_information-SourcePort":"({src_port}\d{1,100})".+?"network_information-DestinationPort":"({dest_port}\d{1,100})".+?"computer":"({src_host}[^"]{1,2000})".+?"network_information-DestinationAddress":"({dest_ip}[^"]{1,2000})"""",
    """"network_information-Protocol":"({protocol_id}[^"]{1,2000})"""",
    """"application_information-ProcessID":"({pid}\d{1,100})""",
    """"application_information-ApplicationName":"({process}({directory}.+)[\\\/]({process_name}.+?))"""",
    """"category":"({category}[^"]{1,2000})"""",
    """"filter_information-LayerName":"({layer_name}[^"]{1,2000})"""",
  ]
  DupFields = ["directory->process_directory"]
}
```