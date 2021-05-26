#### Parser Content
```Java
{
Name = s-microsoft-dhcp
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "dhcp"
  TimeFormat = "MM/dd/yy,HH:mm:ss"
  Conditions = [ ",Assign," ]
  Fields = [ """({time}\d\d/\d\d/\d\d,\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})[\+\-]\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\[""",
    """Assign,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({dest_host}[^,]{1,2000}),(({src_mac}[\w]{12}),)?""",
    """"{1,20}hostname\\"{1,20}:\\"{1,20}({host}[^\\"]{1,2000})""",
    """({time}\d\d/\d\d/\d\d,\d\d:\d\d:\d\d)""",
    """"{1,20}mac\\"{1,20}:\[\\"{1,20}({src_mac}[^\\"]{1,2000})""",
    """"{1,20}ip\\"{1,20}:\[\\"{1,20}({src_ip}[^\\"]{1,2000})""",
    """"{1,20}host\\"{1,20}.+?os.+?family\\"{1,20}:\\"{1,20}({os}[^\\]{1,2000})""",
    """"{1,20}ephemeral_id\\"{1,20}:\\"{1,20}({ephemeral_id}[^\\"]{1,2000})""",
    """<Identifier>({host}[^<]{1,2000})<\/"""
  ]
  DupFields = [ "dest_host->user" ]
}
```