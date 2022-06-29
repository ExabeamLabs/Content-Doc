#### Parser Content
```Java
{
Name = paloalto-firewall-traffic-drop
  DataType = "network-connection"
  Conditions = [ """"LogType":"TRAFFIC"""", """"Action":"deny"""", """"Subtype":"drop"""" ]
  Fields = ${PaloAltoParserTemplates.paloalto-vpn.Fields}[
    """"Action":"({action}[^"]{1,20000})"""",
    """"NATSource":"({src_translated_ip}[a-fA-F\d:.]{1,2000})""",
    """"NATDestination":"({dest_translated_ip}[a-fA-F\d:.]{1,2000})""",
    """"NATSourcePort":({src_translated_port}\d{1,100})""",
    """"NATDestinationPort":({dest_translated_port}\d{1,100})""",
    """"Bytes":({bytes}\d{1,100}),""",
    """"BytesSent":({bytes_out}\d{1,100}),""",
    """"BytesReceived":({bytes_in}\d{1,100}),""",
    """"URLCategory":"({category}[^"]{1,2000})""""
  ]

paloalto-vpn = {
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,9}Z)""",
    """"host":"({host}[^"]{1,2000})"""",
    """"DeviceName":"({host}[^"\s]{1,2000})"""",
    """"PrivateIPv(4|6)":"({src_ip}[a-fA-F\d:.]{1,2000})""",
    """"PublicIPv(4|6)":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"Source(Address|IP)":"({src_ip}[a-fA-F\d:.]{1,2000})""",
    """"DestinationAddress":"({dest_ip}[a-fA-F\d:.]{1,2000})""",
    """"(Source)?User(Name)?":"((na|NA|({domain}[^"\\]{1,2000}))\\{1,20})?(({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})|({user}[^"]{1,2000}))"""", 
    """"SourcePort":({src_port}\d{1,100})""",
    """"DestinationPort":({dest_port}\d{1,100})""",
    """"Protocol":"({protocol}[^"]{1,2000})"""",
    """"LogType":"({log_type}[^"]{1,2000})""""
  
}
```