#### Parser Content
```Java
{
Name = cef-microsoft-dns-query
  DataType = "dns-query"
  Conditions = [ """CEF:""", """destinationServiceName=Office 365""", """DNS query""", """Run command:""" ]
  Fields = ${MSParserTemplates.cef-azure-app-activity-1.Fields}[
    """<b>DNS query</b> <b>({query}.+?)</b>""",
  ]
}
```