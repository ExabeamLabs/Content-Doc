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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"rt":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"name":\s{0,100}"({activity}[^":]{1,2000}):\s({device_type}[^"]{1,2000})""",
    """"name":\s{0,100}"({activity_details}[^"]{1,2000})""",
    """"dhost":\s{0,100}"({src_host}[^"]{1,2000})""",
    """"suser":\s{0,100}"(?:n\/a|({user_fullname}[^"\\,]{1,2000}))"""",
    """"suser":\s{0,100}"(n\/a|({user_lastname}[^",\\\s]{1,2000}),\s{0,100}({user_firstname}[^,"\\\s]{1,2000}))""",
    """"suser":\s{0,100}"(?:n\/a|({user}[^",\\\s]{1,2000}))"""",
    """"suser":\s{0,100}"(({domain}[^\\",]{1,2000})\\+)?({user}[^",\\\/\s]{1,2000})"""",
    """"id":\s{0,100}"({device_id}[^"]{1,2000})""",
  ]
}
```