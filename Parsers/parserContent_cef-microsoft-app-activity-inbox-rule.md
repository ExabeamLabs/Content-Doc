#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-inbox-rule
  Product = Microsoft Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|resource-property-updated|""", """"New-InboxRule"""" ]
  Fields = ${MSParserTemplates.cef-microsoft-app-activity.Fields}[
    """"(?i)({activity}ForwardTo|delivertomailboxandforward)""""
    """"ForwardTo":"+(smtp:)?({target}[^"]+@({target_domain}[^"]+))""""
    """"SubjectOrBodyContainsWords":"({filter_key_words}[^"]+)"""
    """"ResultStatus":"({outcome}[^"]+)"""",
  ]
}
```