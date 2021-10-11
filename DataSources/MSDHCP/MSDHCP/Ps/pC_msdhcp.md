#### Parser Content
```Java
{
Name = ms-dhcp
  Vendor = MSDHCP
  Product = MSDHCP
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """[][]""", """[DHCP]""", """ MSDHCP """, """,DNS Update Successful,""" ]
  Fields = [
    """\[\]\[\]\[({src_ip}[a-fA-F\d.:]{1,2000})\]\[({event_code}\d{1,100})\]\[DHCP\]""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s{1,100}({host}[\w.\-]{1,2000})""",
    """"([^,]{0,2000},)\d{1,100}\/\d{1,100}\/\d{1,100},\d{1,100}:\d{1,100}:\d{1,100},({activity}[^,]{1,2000}),(|({dest_ip}[a-fA-F\d.:]{1,2000})),(|({dest_host}[\w\-.]{1,2000})),(|({dest_mac}[^,\s]{1,2000})),""",
  ]
  DupFields = [ "event_code->service_id" ]
}
```