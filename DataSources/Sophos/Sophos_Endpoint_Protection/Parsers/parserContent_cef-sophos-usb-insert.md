#### Parser Content
```Java
{
Name = cef-sophos-usb-insert
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = ArcSight
  DataType = "usb-insert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|sophos|sophos central|""", """|Event::Endpoint::Device::AlertedOnly|""", """group=PERIPHERALS""", """|Peripheral allowed:""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """\Wrt=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CEF:([^\|]*\|){5}({activity}[^:\|]+):\s({device_type}[^\|]+)""",
    """CEF:([^\|]*\|){5}({activity_details}[^\|]+)""",
    """\Wdhost=({src_host}[\w\-.]+)\s{1,100}(\w+=|$)""",
    """\Wsuser=((({dest_host}[^\s\\]+)\\+)({user}[^\s\\]+)|(n\/a|({user_fullname}[^\\]+?)))\s{1,100}(\w+=|$)""",
    """\Wid=({device_id}[^\s]+)""",
  ]
}
```