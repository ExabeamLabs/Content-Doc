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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\Wrt=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CEF:([^\|]{0,2000}\|){5}({activity}[^:\|]{1,2000}):\s({device_type}[^\|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({activity_details}[^\|]{1,2000})""",
    """\Wdhost=({src_host}[\w\-.]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wsuser=((({dest_host}[^\s\\]{1,2000})\\+)({user}[^\s\\]{1,2000})|(n\/a|({user_fullname}[^\\]{1,2000}?)))\s{1,100}(\w+=|$)""",
    """\Wid=({device_id}[^\s]{1,2000})""",
  ]
}
```