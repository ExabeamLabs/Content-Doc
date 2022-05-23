#### Parser Content
```Java
{
Name = paloalto-ngfw-network-connection
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"source":"Palo Alto Networks FLS LF"""", """"LogType":"DECRYPTION"""", """"SubType":"start"""", """"FromZone":"""", """"ToZone":"""" ]
  Fields = [
    """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)"""",
    """"host":"({host}[^"]{1,2000})"""",
    """"SourceUser":"({user_email}[^"@]{1,2000}@[^"]{1,2000})"""",
    """"SourceAddress":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """"DestinationAddress":({dest_ip}[a-fA-F\d:.]{1,2000})"""",
    """"SourcePort":({src_port}\d{1,100})""",
    """"DestinationPort":({dest_port}\d{1,100})""",
    """"NATSource":"({src_translated_ip}[a-fA-F\d:.]{1,2000})"""",
    """"NATDestination":"({dest_translated_ip}[a-fA-F\d:.]{1,2000})"""",
    """"NATSourcePort":({src_translated_port}\d{1,100})""",
    """"NATDestinationPort":({dest_translated_port}\d{1,100})""",
    """"LogType":"({event_name}[^"]{1,2000})"""",
    """"SubType:"({activity}[^"]{1,2000})"""",
    """"Action":"({outcome}[^"]{1,2000})"""",
    """"Protocol":"({protocol}[^"]{1,2000})"""",
    """"Rule":"({rule}[^"]{1,2000})"""",
    """"PolicyName":"({additional_info}[^"]{1,2000})"""",
    """"FromZone":"({src_network_zone}[^"]{1,2000})"""",
    """"ToZone":"({dest_network_zone}[^"]{1,2000})""""
  ]


}
```