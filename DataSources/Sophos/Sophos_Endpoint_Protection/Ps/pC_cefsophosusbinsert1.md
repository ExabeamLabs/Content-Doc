#### Parser Content
```Java
{
Name = cef-sophos-usb-insert-1
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = ArcSight
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """"Event::Endpoint::Device::AlertedOnly"""", """"Peripheral allowed:""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"location":"({host}[\w\-.]{1,2000})""",
    """"when":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"type":"({additional_info}[^"]{1,2000})""",
    """"name":"({activity_details}({activity}Peripheral allowed):\s{0,100}({device_type}[^"]{1,2000}))""",
    """"source":"(n\/a|({user_fullname}[^"\\\(\),]{1,2000}))"""",
    """"source":"(n\/a|({user_lastname}[^",\s]{1,2000}),\s{0,100}({user_firstname}[^,"\s]{1,2000}))""",
    """"source":"(n\/a|(([^\\\s"]{0,2000}\s{1,100}[^\\"]{0,2000}|({domain}[^\\"]{1,2000}))\\+)?({user}[^\\\s"]{1,2000}))"""",
    """"ip":"({src_ip}[A-Fa-f:\d.]{1,2000})""""
  ]
}
```