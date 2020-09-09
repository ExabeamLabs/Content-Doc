#### Parser Content
```Java
{
Name = openvpn-auth-successful
  DataType = "authentication-successful"
  Conditions = [ """id=ArrayOS""", """Authentication succeeded""", """type=vpn""" ]
}

${OpenvpnParserTemplates.openvpn-events}{
  Name = openvpn-auth-failed
  DataType = "authentication-failed"
  Conditions = [ """id=ArrayOS""", """Authentication failed""", """type=vpn""" ]
}

${OpenvpnParserTemplates.openvpn-events}{
  Name = openvpn-vpn-end
  DataType = "vpn-end"
  Conditions = [ """id=ArrayOS""", """logged out successfully""", """type=vpn""" ]
}

${OpenvpnParserTemplates.openvpn-events}{
  Name = openvpn-vpn-end-1
  DataType = "vpn-end"
  Conditions = [ """id=ArrayOS""", """TCP tunnel""", """has been terminated for""", """type=vpn""" ]
}

${OpenvpnParserTemplates.openvpn-events}{
  Name = openvpn-vpn-login-1
  DataType = "vpn-login"
  Conditions = [ """id=ArrayOS""", """A new TCP tunnel has been established successfully""", """type=vpn""" ]
}

{
  Name = q-varonis-file-activity
  Vendor = Varonis
  Product = Data Security Platform
  Lms = QRadar
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ """LEEF:""", """|Varonis|DatAdvantage|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """devTime=({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
    """accountName=({user}.+?)\s+(\w+=|$)""",
    """domain=(|({domain}.+?))\s+(\w+=|$)""",
    """src=({dest_ip}[A-Fa-f:\d.]+)\s+(\w+=|$)""",
    """Event_Type=({accesses}.+?)\s+(\w+=|$)""",
    """Event_Status=({outcome}.+?)\s+(\w+=|$)""",
    """Affected_Object=(|({file_path}.+?))\s+(\w+=|$)""",
    """Affected_Object=(({file_parent}[^=]+?)\\+)?({file_name}[^\\]+?(\.({file_ext}[^\.\s]+))?)\s+(\w+=|$)""",
    """Affected_Object_Path=(|({file_path}.+?))\s+(\w+=|$)""",
    """Affected_Object_Path=({file_parent}.+?)\\[^\\]+\s+(\w+=|$)""",
  ]
  DupFields = [ "accesses->event_code" ]
}
```