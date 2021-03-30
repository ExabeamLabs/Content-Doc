#### Parser Content
```Java
{
Name = s-microsoft-dns-renew
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "dhcp"
  TimeFormat = "MM/dd/yy,HH:mm:ss"
  Conditions = [ ",Renew," ]
  Fields = [ 
    """({time}\d\d/\d\d/\d\d,\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """"+hostname\\"+:\\"+({host}[^\\"]+)"""
    """Renew,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({dest_host}[^,]+),""",
    """"+mac\\"+:\[\\"+({src_mac}[^\\"]+)""",
    """"+ip\\"+:\[\\"+({src_ip}[^\\"]+)""",
    """"+host\\"+.+?os.+?family\\"+:\\"+({os}[^\\]+)""",
    
    
  ]
  DupFields = [ "dest_host->user" ]
}
```