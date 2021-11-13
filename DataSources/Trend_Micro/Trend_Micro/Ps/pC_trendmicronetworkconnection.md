#### Parser Content
```Java
{
Name = trendmicro-network-connection
  Vendor = Trend Micro
  Product = Trend Micro
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""TrendMicroDsTenant""" , """TrendMicroDsFrameType=IP"""]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\|dvchost=({host}[^\|\s"]{1,2000})""",
    """\|dst=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|dpt=({src_port}\d{1,100})""",
    """\|src=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|spt=({dest_port}\d{1,100})""",
    """\|proto=({protocol}[^\|]{1,2000})"""
    """\|smac=({source_mac}[^\|]{1,2000})""",
    """\|in=({bytes}[^\|]{1,2000})""",
    """\|act=({activity}[^\|]{1,2000})"""
  ]


}
```