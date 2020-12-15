#### Parser Content
```Java
{
Name = cc-pulsesecure-account-deleted
  DataType = "account-deleted"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """User Accounts modified.""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """Removed username (({target_domain}[^\\\.]+)\\)?({target_user}[^\\\s]+)"""
  ]
}
```