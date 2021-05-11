#### Parser Content
```Java
{
Name = s-microsoft-dns-update
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "dhcp"
  TimeFormat = "MM/dd/yy,HH:mm:ss"
  Conditions = [ """,DNS Update Successful,""", """":"""" ]
  Fields = ["""({time}\d\d/\d\d/\d\d,\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """DNS Update Successful,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({dest_host}[^,]+),""",
    """"{1,20}hostname\\"{1,20}:\\"{1,20}({host}[^\\"]+)"""
    """"{1,20}mac\\"{1,20}:\[\\"{1,20}({src_mac}[^\\"]+)""",
    """"{1,20}ip\\"{1,20}:\[\\"{1,20}({src_ip}[^\\"]+)""",
    """"{1,20}host\\"{1,20}[^}]+os[^}]+family\\"{1,20}:\\"{1,20}({os}[^\\]+)""",
    """<Identifier>({host}[^<]+)<\/"""
  ]
  DupFields = [ "dest_host->user" ]
}
```