#### Parser Content
```Java
{
Name = ping-auth-failed-4
  DataType = "authentication-failed"
  Conditions = [ """| AUTHN_ATTEMPT|""", """failure|""" ]
  Fields = ${PingParserTemplates.ping-events.Fields} [
    """(\|\s*(AUTHN_ATTEMPT|OAuth|SSO)\s*\|)\s*([^\|]*\|){9}\s*(|({failure_reason}[^\|]*?))\s*\|""",
  ]
}
```