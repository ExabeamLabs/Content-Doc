#### Parser Content
```Java
{
Name = s-n3k-dhcp
    Vendor = N3K
  Product = N3K
    Lms = Splunk
    DataType = "dhcp"
    TimeFormat = "epoch"
    Conditions = [ """maskedIP""", """_time""", """Domain""" ]
    Fields = [
      """"_time":\s+"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
      """\sinfo_search_time=({time}\d+\.\d+)""",
      """("|\s)Host(":\s+|=)"?({dest_host}[^",]+)""",
      """("|\s)maskedIP(":\s+|=)"({dest_ip}[^"]+)""",
      """("|\s)MAC(":\s+|=)"?({src_mac}[^",]+)""",
    ]
    DupFields = [ "dest_host->user" ]
  }
```