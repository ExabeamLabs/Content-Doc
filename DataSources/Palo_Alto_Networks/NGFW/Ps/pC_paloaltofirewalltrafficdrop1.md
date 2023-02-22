#### Parser Content
```Java
{
Name = paloalto-firewall-traffic-drop-1
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"LogType":"TRAFFIC"""", """"Action":"drop"""", """"Subtype":"drop"""", """"Rule":"""" ]
  Fields = [
  """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,6}Z)"""
  """"host":"({host}[\w\-.]{1,2000})"""
  """"DeviceName":"({host}[\w\-.]{1,2000})"""
  """"SourceAddress":"({src_ip}[A-Fa-f\d:.]{1,2000})"""
  """"DestinationAddress":"({dest_ip}[a-fA-F\d:.]{1,2000})"""
  """"SourcePort":({src_port}\d{1,5})"""
  """"DestinationPort":({dest_port}\d{1,5})"""
  """"LogType":"({log_type}[^"]{1,2000})""""
  """"Protocol":"({protocol}[^"]{1,2000})""""
  """"Action":"({action}[^"]{1,20000})""""
  """"Bytes":({bytes}\d{1,100}),"""
  """"BytesSent":({bytes_out}\d{1,100}),"""
  """"BytesReceived":({bytes_in}\d{1,100}),"""
  """"URLCategory":"({category}[^"]{1,2000})""""  
  ]


}
```