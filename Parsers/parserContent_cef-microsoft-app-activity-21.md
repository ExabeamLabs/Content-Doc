#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-21
  Product = Microsoft Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|resource-renamed|""" ]
}

${MSParserTemplates.cef-microsoft-app-activity} {
  Name = cef-microsoft-app-activity-22
  Product = Microsoft Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|resource-uploaded|""" ]
}
```