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
    """[\|\s]dvchost=({host}[^\|\s"]{1,2000})""",
    """[\|\s]dst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """[\|\s]dpt=({dest_port}\d{1,100})""",
    """[\|\s]src=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """[\|\s]spt=({src_port}\d{1,100})""",
    """[\|\s]proto=({protocol}[^\|\s]{1,2000}?)[\s\|]""",
    """[\|\s]smac=({source_mac}[^\|\s]{1,2000})""",
    """[\|\s]in=({bytes}\d{1,100})""",
    """[\|\s]act=({activity}[^\|\s]{1,2000})""",
    """[\|\s]dmac=({dest_mac}[^\s\|]{1,2000}?)[\s\|]""",
    """CEF:(\s{0,10}\d{1,10})\|(([^\|]{1,2000})\|){4}({alert_name}[^\|]{1,2000})""",
  ]


}
```