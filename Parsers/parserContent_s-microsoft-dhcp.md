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
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+)[\+\-]\d+:\d+\s+({host}[\w\-.]+)\s+\[""",
    """Assign,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({dest_host}[^,]+),(({src_mac}[\w]{12}),)?""",
    """"+hostname\\"+:\\"+({host}[^\\"]+)""",
    """({time}\d\d/\d\d/\d\d,\d\d:\d\d:\d\d)""",
    """"+mac\\"+:\[\\"+({src_mac}[^\\"]+)""",
    """"+ip\\"+:\[\\"+({src_ip}[^\\"]+)""",
    """"+host\\"+.+?os.+?family\\"+:\\"+({os}[^\\]+)""",
    """"+ephemeral_id\\"+:\\"+({ephemeral_id}[^\\"]+)""",
    """<Identifier>({host}[^<]+)<\/"""
  ]
  DupFields = [ "dest_host->user" ]
}
```