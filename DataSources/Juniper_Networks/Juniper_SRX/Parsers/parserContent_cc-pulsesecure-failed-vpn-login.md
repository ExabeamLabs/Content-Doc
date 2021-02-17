#### Parser Content
```Java
{
Name = cc-pulsesecure-failed-vpn-login
  DataType = "failed-vpn-login"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """Login failed using auth server""", """Reason:""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """Reason:\s+({failure_reason}[^"]+?)\s*"""",
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s+Default Network::(({domain}[^\\]+)\\)?({user}[^\(]+)\(({realm}[^\)]+)?\)\[([^\-]*)\-\s*({failure_reason}[^\:\.]+)?\s*"""
  ]
}
```