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
    """({time}\d+\w+\d\d\d\d,\d+:\d+:\d+),(|({host}[^,]*)),log,({action}accept),([^,]*,){6}(|({rule}[^,]*)),[^,]*,(|({src_ip}[^,]*)),(|({dest_ip}[^,]*)),(|({protocol}[^,]*)),(|({dest_port}\d+)),(|({src_port}\d+)),([^,]*,){3}(|({src_translated_ip}[^,]*)),(|({dest_translated_ip}[^,]*)),([^,]*,){2}(|({dest_translated_port}[^,]*)),(|({src_translated_port}[^,]*)),([^,]*,){2}(|({user}[^,]*)),"""
  ]
}
```