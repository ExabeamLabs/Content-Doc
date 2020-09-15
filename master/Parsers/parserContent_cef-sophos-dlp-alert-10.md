#### Parser Content
```Java
{
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
  Name = cef-sophos-dlp-alert-13
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = ArcSight
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [  """CEF:""", """Event::Endpoint::DataLossPreventionAutomaticallyAllowed""", """group=DATA_LOSS_PREVENTION""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"location":"({host}[\w\-.]+)"""",
    """({host}[\w\-.]+)\s+Skyformation""",
    """"when":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"type":"({alert_type}Event[^"]+)""",
    """"severity":"({alert_severity}[^"]+)""",
    """"id":"({alert_id}[^"]+)""",
    """"location":"({src_host}[^"]+)""",
    """"name":\s*"({alert_name}.+?)\s+(\w+:)"""
    """"name":\s*"({additional_info}[^"]+)"""
    """"name".+?Username:\s*(({domain}[^\\]+)\\+)?({user}[^\s\\]+)\s""",
    """"name".+?Rule names:\s*′({rule}[^′]+)""",
    """"name".+?User action:\s*({activity}.+?)\s+(\w+\s+\w+:)""",
    """"name".+?Application Name:\s+({app}.+?)\s+Data Control action:""",
    """"name".+?Data Control action:\s*({outcome}[^\s]+)\s""",
    """"name".+?File type:\s*({file_type}.+?)\s+File size:\s*({bytes}\d+)\s""",
    """"name".+?Source path:\s*({target}.+?)\s*(\w+\s+\w+:|")"""
  ]
}

{
  Name = cef-sophos-usb-insert-1
  Vendor = Sophos
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