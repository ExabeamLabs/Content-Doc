#### Parser Content
```Java
{
Name = s-microsoft-dhcp
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ ",Assign," ]
  Fields = [ """({time}\d\d/\d\d/\d\d,\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+)[\+\-]\d+:\d+\s+({host}[\w\-.]+)\s+\[""",
    """Assign,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({dest_host}[^,]+),"""
  ]
  DupFields = [ "dest_host->user" ]
}
```