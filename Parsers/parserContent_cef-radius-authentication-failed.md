#### Parser Content
```Java
{
Name = cef-radius-authentication-failed
  Product = Aruba Wireless controller
  Conditions = [ """CEF:""", """|Aruba Networks|ClearPass|""", """|RADIUS Failed Authentications|""" ]
  Fields=${ArubaClearParserTemplates.cef-aruba-nac-logon-1.Fields}[
    """Reason\\=\[({failure_reason}.+?)\]""",
    
  ]
}
```