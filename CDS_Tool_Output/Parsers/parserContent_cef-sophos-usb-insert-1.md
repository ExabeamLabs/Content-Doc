#### Parser Content
```Java
{
Name = cef-sophos-usb-insert-1
  Vendor = Sophos EPP
  Product = Sophos Endpoint Protection
  Lms = ArcSight
  DataType = "usb-insert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """"Event::Endpoint::Device::AlertedOnly"""", """"Peripheral allowed:""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"location":"({host}[\w\-.]+)"""",
    """"when":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"type":"({additional_info}[^"]+)""",
    """"name":"({activity_details}({activity}Peripheral allowed):\s*({device_type}[^"]+))""",
    """"source":"(n\/a|({user_fullname}[^"\\\(\),]+))"""",
    """"source":"(n\/a|({user_lastname}[^",\s]+),\s*({user_firstname}[^,"\s]+))""",
    """"source":"(n\/a|(([^\\\s"]*\s+[^\\"]*|({domain}[^\\"]+))\\+)?({user}[^\\\s"]+))"""",
  ]
}
```