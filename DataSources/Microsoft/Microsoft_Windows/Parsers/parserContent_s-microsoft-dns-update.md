#### Parser Content
```Java
{
Name = s-microsoft-dns-update
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "dhcp"
  TimeFormat = "MM/dd/yy,HH:mm:ss"
  Conditions = [ ",DNS Update Successful," ]
  Fields = ["""({time}\d\d/\d\d/\d\d,\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """DNS Update Successful,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({dest_host}[^,]+),""",
    """"+hostname\\"+:\\"+({host}[^\\"]+)"""
    """"+mac\\"+:\[\\"+({src_mac}[^\\"]+)""",
    """"+ip\\"+:\[\\"+({src_ip}[^\\"]+)""",
    """"+host\\"+.+?os.+?family\\"+:\\"+({os}[^\\]+)""",
  ]
  DupFields = [ "dest_host->user" ]
}
```