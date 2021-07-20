#### Parser Content
```Java
{
Name = s-intrust-dns
    Vendor = Quest InTrust
  Product = Quest InTrust
    Lms = Splunk
    DataType = "dhcp"
    TimeFormat = "MM/dd/yyyy HH:mm:ss a"
    Conditions = [ """Message=DNS record was""","""DNS Record Data:""" ]
    Fields = [ """exabeam_raw=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (AM|PM|am|pm))\s{0,100}LogName=""",
      """ComputerName=({host}.+?)\s{0,100}Category""",
      """DNS Record Name[:\s]{0,2000}({dest_host}[^\s.]{1,2000})""",
      """\s(New )?DNS Record Data[:\s]{0,2000}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    ]
    DupFields = [ "dest_host->user" ]
  }
```