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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """"rt":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"name":\s{0,100}"({activity}[^":]+):\s({device_type}[^"]+)""",
    """"name":\s{0,100}"({activity_details}[^"]+)""",
    """"dhost":\s{0,100}"({src_host}[^"]+)""",
    """"suser":\s{0,100}"(?:n\/a|({user_fullname}[^"\\,]+))"""",
    """"suser":\s{0,100}"(n\/a|({user_lastname}[^",\\\s]+),\s{0,100}({user_firstname}[^,"\\\s]+))""",
    """"suser":\s{0,100}"(?:n\/a|({user}[^",\\\s]+))"""",
    """"suser":\s{0,100}"(({domain}[^\\",]+)\\+)?({user}[^",\\\/\s]+)"""",
    """"id":\s{0,100}"({device_id}[^"]+)""",
  ]
}
```