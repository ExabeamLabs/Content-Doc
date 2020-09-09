#### Parser Content
```Java
{
Name = cef-pan-vpn-login-failed-1
  DataType = "failed-vpn-login"
  Conditions = [ """CEF:""", """|Palo Alto Networks|""", """globalprotect""", """GlobalProtect gateway user login failed""" ]
  Fields = ${PaloAltoParserTemplates.cef-pan-vpn-event.Fields}[
    """\Wreason=({failure_reason}.+?)(\s+\w+=|\s*$)""",
  ]
}
```