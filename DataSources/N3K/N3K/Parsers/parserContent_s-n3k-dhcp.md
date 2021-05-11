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
      """"_time":\s{1,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
      """\sinfo_search_time=({time}\d{1,100}\.\d{1,100})""",
      """("|\s)Host(":\s{1,100}|=)"?({dest_host}[^",]+)""",
      """("|\s)maskedIP(":\s{1,100}|=)"({dest_ip}[^"]+)""",
      """("|\s)MAC(":\s{1,100}|=)"?({src_mac}[^",]+)""",
    ]
    DupFields = [ "dest_host->user" ]
  }
```