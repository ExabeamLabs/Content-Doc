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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """"location":"({host}[\w\-.]+)""",
    """"when":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"type":"({additional_info}[^"]+)""",
    """"name":"({activity_details}({activity}Peripheral allowed):\s{0,100}({device_type}[^"]+))""",
    """"source":"(n\/a|({user_fullname}[^"\\\(\),]+))"""",
    """"source":"(n\/a|({user_lastname}[^",\s]+),\s{0,100}({user_firstname}[^,"\s]+))""",
    """"source":"(n\/a|(([^\\\s"]*\s{1,100}[^\\"]*|({domain}[^\\"]+))\\+)?({user}[^\\\s"]+))"""",
    """"ip":"({src_ip}[A-Fa-f:\d.]+)""""
  ]
}
```