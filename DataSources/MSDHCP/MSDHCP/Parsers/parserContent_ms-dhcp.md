#### Parser Content
```Java
{
Name = ms-dhcp
  Vendor = MSDHCP
  Product = MSDHCP
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """[][]""", """[DHCP]""", """ MSDHCP """ ]
  Fields = [
    """\[\]\[\]\[({src_ip}[a-fA-F\d.:]+)\]\[({event_code}\d+)\]\[DHCP\]""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s+({host}[\w.\-]+)""",
    """"([^,]*,)\d+\/\d+\/\d+,\d+:\d+:\d+,({activity}[^,]+),(|({dest_ip}[a-fA-F\d.:]+)),(|({dest_host}[\w\-.]+)),(|({dest_mac}[^,\s]+)),""",
  ]
  DupFields = [ "event_code->service_id" ]
}
```