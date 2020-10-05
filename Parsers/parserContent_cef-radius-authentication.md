#### Parser Content
```Java
{
Name = cef-radius-authentication
  Product = Aruba Wireless controller
  Conditions = [ """CEF:""", """|Aruba Networks|ClearPass|""", """|RADIUS Authentications|""" ]
  Fields=${ArubaClearParserTemplates.cef-aruba-nac-logon-1.Fields}[
   ]
  DupFields = [ "src_ip->dest_ip" ]
}
```