#### Parser Content
```Java
{
Name = q-adfs-auth-failed-2
  DataType = "authentication-failed"
  Conditions = [ """Message=Token validation failed""", """EventIDCode=411""" ]
  Fields = ${MicrosoftParserTemplates.q-adfs-auth.Fields}[
    """Token Type:\s*({auth_method}.+?)\s*Client IP:""",
    """Exception details:\s*({additional_info}.{1,250})""",
    """({src_ip}[a-fA-F\d.:]+)\s*Error message:""",
    """Error message:\s*({failure_reason}.+?)\s*Exception details:""",
  ]
  DupFields = [ "account->user" ]
}
```