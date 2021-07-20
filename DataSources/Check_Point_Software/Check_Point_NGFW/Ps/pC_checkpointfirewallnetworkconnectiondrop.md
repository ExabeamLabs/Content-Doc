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
    """({time}\d{1,100}\w+\d\d\d\d,\d{1,100}:\d{1,100}:\d{1,100}),(|({host}[^,]{0,2000})),log,({action}drop),([^,]{0,2000}
```