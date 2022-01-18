#### Parser Content
```Java
{
Name = microsoft-dns-renew-jp
  TimeFormat = "MM/dd/yy,HH:mm:ssZ"
  Conditions = [ """,更新,""" ]

microsoft-dns-renew-jp = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "dhcp"
  Fields = [ 
    """({time}\d\d/\d\d/\d\d,\d\d:\d\d:\d\d),""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})[\+\-]\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\[""",
    """({time}\d{1,100}\/\d{1,100}\/\d{1,100},\d{1,100}:\d{1,100}:\d{1,100}[\+\-]\d{1,100}:\d{1,100})""",
    """<Identifier>({host}[^<]{1,2000})<\/Identifier>""",
    """,(DNS.*)?(更新|要求|成功|更新成功)([^,]{1,2000})?,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({dest_host}[^,]{1,2000}),(|({mac_address}[^,]{1,2000}))?,"""
  ]
  DupFields = [ "dest_host->user" 
}
```