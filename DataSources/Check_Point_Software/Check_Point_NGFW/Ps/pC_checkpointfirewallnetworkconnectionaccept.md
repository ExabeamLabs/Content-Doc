#### Parser Content
```Java
{
Name = checkpoint-firewall-network-connection-accept
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "ddMMMyyyy','HH:mm:ss"
  Conditions = [ """,log,accept,""" ]
  Fields = [
    """({time}\d{1,100}\w+\d\d\d\d,\d{1,100}:\d{1,100}:\d{1,100}),(|({host}[^,]{0,2000})),log,({action}accept),([^,]{0,2000},){6}(|({rule}[^,]{0,2000})),[^,]{0,2000},(|({src_ip}[^,]{0,2000})),(|({dest_ip}[^,]{0,2000})),(|({protocol}[^,]{0,2000})),(|({dest_port}\d{1,100})),(|({src_port}\d{1,100})),([^,]{0,2000},){3}(|({src_translated_ip}[^,]{0,2000})),(|({dest_translated_ip}[^,]{0,2000})),([^,]{0,2000},){2}(|({dest_translated_port}[^,]{0,2000})),(|({src_translated_port}[^,]{0,2000})),([^,]{0,2000},){2}(|({user}[^,]{0,2000})),"""
  ]
}
```