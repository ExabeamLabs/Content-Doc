#### Parser Content
```Java
{
Name = s-intrust-dns
    Vendor = Quest InTrust
    Lms = Splunk
    DataType = "dhcp"
    TimeFormat = "MM/dd/yyyy HH:mm:ss a"
    Conditions = [ """Message=DNS record was""","""DNS Record Data:""" ]
    Fields = [ """exabeam_raw=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (AM|PM|am|pm))\s*LogName=""",
      """ComputerName=({host}.+?)\s*Category""",
      """DNS Record Name[:\s]*({dest_host}[^\s.]+)""",
      """\s(New )?DNS Record Data[:\s]*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    ]
    DupFields = [ "dest_host->user" ]
  }
```