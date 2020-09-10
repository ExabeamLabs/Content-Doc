#### Parser Content
```Java
{
Name = msnetwork-nac-logon-5
  Vendor = Microsoft
  Product = Microsoft NPS
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "MM/dd/yyyy,HH:mm:ss"
  Conditions = [ ""","IAS",""", """",2,"""" ]
  Fields = [
    """({host}[^"]+)","IAS",({time}\d\d\/\d\d\/\d\d\d\d,\d\d:\d\d:\d\d),(|({outcome}\d+)),(|"({user}[^"]+)"),([^,]*,){9}(|"({src_ip}[^"]+)"),(|"({src_host}[^"]+)"),""",
    """"({dest_ip}[^"]+)",[^,]*,\s*$""",
  ]
}
```