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
    """"{1,20}hostname\\"{1,20}:\\"{1,20}({host}[^\\"]+)"""
    """Renew,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({dest_host}[^,]+),(({src_mac}[\w]{12}),)?""",
    """"{1,20}mac\\"{1,20}:\[\\"{1,20}({src_mac}[^\\"]+)""",
    """"{1,20}ip\\"{1,20}:\[\\"{1,20}({src_ip}[^\\"]+)""",
    """<Identifier>({host}[^<]+)<\/"""
    
  ]
  DupFields = [ "dest_host->user" ]
}
```