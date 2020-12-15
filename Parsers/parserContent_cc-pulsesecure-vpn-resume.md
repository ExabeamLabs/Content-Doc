#### Parser Content
```Java
{
Name = cc-pulsesecure-vpn-resume
  DataType = "access-control"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """Session resumed from user agent '""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s+(Default Network|Root)::(({domain}[^\\]+)\\)?({user}[^\(]+)\(({realm}[^\)]+)?\)(\[({resource}[^\]]+)\])?"""
  ]
}
```