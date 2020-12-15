#### Parser Content
```Java
{
Name = cc-pulsesecure-key-exchange
  DataType = "vpn-connection"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """Key Exchange number""", """occurred for user with""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """({additional_info}Key Exchange number \d+ occurred) for user with NCIP ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```