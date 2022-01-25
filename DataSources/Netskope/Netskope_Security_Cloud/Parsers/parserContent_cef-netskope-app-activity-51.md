#### Parser Content
```Java
{
Name = cef-netskope-app-activity-51
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"activity":""""]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"timestamp":\s{0,100}({time}\d{1,100})""",
    """requestClientApplication=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """"app":\s{0,100}"\[?({app}[^"\]]{1,2000})""",
    """"srcip":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"object":\s{0,100}"(\s{1,100}"|(\s{0,100}(Unknown Unknown|unknown|Unknown|null|({object}[^"]{1,2000}?))\s{0,100}"))""",
    """"user":\s{0,100}"(unknown|(({user_email}[^\s@"]{1,2000}@[^\s@"]{1,2000}\.[^\s@"]{1,2000})|(({domain}[^\s"@\\\/]{1,2000})[\\\/]{1,2000})?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({user}[^\s"@\\\/]{1,2000}))))"""",
    """"activity":\s{0,100}"({activity}[^"]{1,2000})"""",
    """msg=({additional_info}[^=\.]{1,2000})""",
  ]
}
```