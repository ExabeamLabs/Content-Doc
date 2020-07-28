#### Parser Content
```Java
{
Name = sophos-usb-insert
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"Event::Endpoint::Device::""", """"name": "Peripheral """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"rt":\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"name":\s*"({activity}[^":]+):\s({device_type}[^"]+)""",
    """"name":\s*"({activity_details}[^"]+)""",
    """"dhost":\s*"({src_host}[^"]+)""",
    """"suser":\s*"(?:n\/a|({user_fullname}[^"\\,]+))"""",
    """"suser":\s*"(n\/a|({user_lastname}[^",\\\s]+),\s*({user_firstname}[^,"\\\s]+))""",
    """"suser":\s*"(?:n\/a|({user}[^",\\\s]+))"""",
    """"suser":\s*"(({domain}[^\\",]+)\\+)?({user}[^",\\\/\s]+)"""",
    """"id":\s*"({device_id}[^"]+)""",
  ]
}
```