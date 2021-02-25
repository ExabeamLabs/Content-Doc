#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-19
  Product = Microsoft Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|resource-deleted|""" ]
  Fields = ${MSParserTemplates.cef-microsoft-app-activity.Fields} [
    """"ParentFolder":[^\}]+?"Path":"\\*({object}[^"]+)"""",
    """"DestFolder":[^\}]+?"Path":"\\*({object}[^"]+)"""",
    """\srequest=({outcome}[^\s]+)\s""",
    """"ClientIP":"({src_ip}[A-Fa-f:\d.]+)"""",
    """"Operation":"({activity}[^"]+)"""",
    """LogonUserSid":"({user_sid}[^"]+)"""",
    """Subject":"\s*({subject}[^"]+?)\s*"""",
  ]
}
```