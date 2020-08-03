#### Parser Content
```Java
{
Name = authmgr-authentication-failed
  DataType = "authentication-failed"
  Conditions = [ """client_ip_address=""", """result_action=Authentication Failure""" ]
  Fields = ${RSAParserTemplates.authmgr-authentication.Fields} [
    """,result_reason=({failure_reason}[^,]+?)(\s*$|,)""",
  ]
}
```