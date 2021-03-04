#### Parser Content
```Java
{
Name = authmgr-authentication-failed-1
  DataType = "authentication-failed"
  Conditions = [ """client_ip_address=""", """result_action=Authorization Failure""" ]
  Fields = ${RSAParserTemplates.authmgr-authentication.Fields} [
    """,result_reason=({failure_reason}[^,]+?)(\s*$|,)""",
  ]
}
```