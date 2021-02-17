#### Parser Content
```Java
{
Name = authmgr-authentication-failed-2
  DataType = "authentication-failed"
  Conditions = [ """client_ip_address=""", """result_action=User Token Failed""" ]
  Fields = ${RSAParserTemplates.authmgr-authentication.Fields} [
    """,result_reason=({failure_reason}[^,]+?)(\s*$|,)""",
  ]
}
```