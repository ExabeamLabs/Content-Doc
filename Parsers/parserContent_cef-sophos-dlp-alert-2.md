#### Parser Content
```Java
{
Name = cef-sophos-dlp-alert-2
  Conditions = [ """CEF:""", """"Event::Endpoint::CorePua""", """"group":"PUA"""" ]
}

${SophosParserTemplates.cef-sophos-dlp-alert-1}{
  Name = cef-sophos-dlp-alert-8
  Conditions = [ """CEF:""", """"Event::Endpoint::Core""" ]
}

${SophosParserTemplates.cef-sophos-dlp-alert-1}{
  Name = cef-sophos-dlp-alert-9
  Conditions = [ """CEF:""", """"Event::Endpoint::Enc::""" ]
}

${SophosParserTemplates.cef-sophos-dlp-alert-1}{
  Name = cef-sophos-dlp-alert-10
  Conditions = [ """CEF:""", """"Event::Endpoint::HmpaCryptoGuard""" ]
}

${SophosParserTemplates.cef-sophos-dlp-alert-1}{
  Name = cef-sophos-dlp-alert-11
  Conditions = [ """CEF:""", """"Event::Endpoint::Registered""" ]
}

${SophosParserTemplates.cef-sophos-dlp-alert-1}{
  Name = cef-sophos-dlp-alert-12
  Conditions = [ """CEF:""", """"Event::Endpoint::Reprotected""" ]
}

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