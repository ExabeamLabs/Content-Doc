#### Parser Content
```Java
{
Name = cef-sophos-security-alert-9
  Conditions = [ """CEF:""", """"type":"Event::Endpoint::NotProtected"""" ]
}

${SophosParserTemplates.cef-sophos-security-alert-1} {
  Name = cef-sophos-security-alert-10
  Conditions = [ """CEF:""", """"type":"Event::Endpoint::CoreCleanFailed"""" ]
}

${SophosParserTemplates.cef-sophos-security-alert-1} {
  Name = cef-sophos-security-alert-11
  Conditions = [ """CEF:""", """"type":"Event::Endpoint::CorePuaCleanFailed"""" ]
}

${SophosParserTemplates.cef-sophos-security-alert-1} {
  Name = cef-sophos-security-alert-12
  Conditions = [ """CEF:""", """"type":"Event::Endpoint::HmpaCredGuard"""" ]
}

${SophosParserTemplates.cef-sophos-security-alert-1} {
  Name = cef-sophos-security-alert-13
  Conditions = [ """CEF:""", """"type":"Event::Endpoint::HmpaSafeBrowsing"""" ]
}

${SophosParserTemplates.cef-sophos-security-alert-1} {
  Name = cef-sophos-security-alert-14
  Conditions = [ """CEF:""", """"type":"Event::Endpoint::Threat::PuaDetected"""" ]
}

${SophosParserTemplates.cef-sophos-security-alert-1} {
  Name = cef-sophos-security-alert-15
  Conditions = [ """CEF:""", """"type":"Event::Endpoint::Threat::Detected"""" ]
}

${SophosParserTemplates.cef-sophos-security-alert-1} {
  Name = cef-sophos-security-alert-16
  Conditions = [ """CEF:""", """"type":"Event::Endpoint::UserAutoCreated"""" ]
}

  ${SSAParserTemplates.sophos-security-alert}{
  Name = sophos-security-alert-1
  Conditions = [ """Event::Endpoint::Threat::""" ]
  }

  ${SSAParserTemplates.sophos-security-alert}{
  Name = sophos-security-alert-2
  Conditions = [ """Event::Endpoint::Application::Detected""" ]
  }

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