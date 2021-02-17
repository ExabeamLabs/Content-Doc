#### Parser Content
```Java
{
Name = ping-auth-failed-5
  DataType = "authentication-failed"
  Conditions = [ """| OAuth|""", """failure|""" ]
  Fields = ${PingParserTemplates.ping-events.Fields} [
    """(\|\s*(AUTHN_ATTEMPT|OAuth|SSO)\s*\|)\s*([^\|]*\|){9}\s*(|({failure_reason}[^\|]*?))\s*\|""",
  ]
}
```