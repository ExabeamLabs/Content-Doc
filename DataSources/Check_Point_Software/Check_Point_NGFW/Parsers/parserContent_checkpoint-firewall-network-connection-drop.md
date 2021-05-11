#### Parser Content
```Java
{
Name = checkpoint-firewall-network-connection-drop
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "ddMMMyyyy','HH:mm:ss"
  Conditions = [ """,log,drop,""" ]
  Fields = [
    """({time}\d{1,100}\w+\d\d\d\d,\d{1,100}:\d{1,100}:\d{1,100}),(|({host}[^,]*)),log,({action}drop),([^,]*,){6}(|({rule}[^,]*)),[^,]*,(|({src_ip}[^,]*)),(|({dest_ip}[^,]*)),(|({protocol}[^,]*)),(|({dest_port}\d{1,100})),(|({src_port}\d{1,100})),([^,]*,){3}(|({src_translated_ip}[^,]*)),(|({dest_translated_ip}[^,]*)),([^,]*,){2}(|({dest_translated_port}[^,]*)),(|({src_translated_port}[^,]*)),([^,]*,){2}(|({user}[^,]*)),"""
  ]
}
```