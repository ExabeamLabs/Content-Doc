#### Parser Content
```Java
{
Name = cc-pulsesecure-failed-vpn-login-1
  DataType = "failed-vpn-login"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """Login failed.""", """Reason:""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """Reason:\s+({failure_reason}[^"]+)""""
  ]
}
```