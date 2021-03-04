#### Parser Content
```Java
{
Name = cef-unix-local-logon-2
  DataType = "local-logon"
  Conditions = [ """CEF""", """Unix|Unix""", """|VMCACheckAccessKrb: Authenticated user""" ]
  Fields = ${UnixParserTemplates.cef-unix-template.Fields}[
    """VMCACheckAccessKrb: Authenticated user ({user}[^\.\s@]+)(\.({domain}[^\|\s]+))?"""
  ]
}
```