#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-37
  Product = Office 365
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """dproc=Graph Directory Audit""" ]
  Fields = ${MSParserTemplates.cef-microsoft-app-activity.Fields}[
    """\WsourceServiceName=(|({app}.+?))\s+(\w+=|$)""",
    """\Wext_result=(|({outcome}.+?))\s+(\w+=|$)""",
    """\Wext_targetResources_0__modifiedProperties_1__newValue=(|(\[|")({object}.+?)(\]|"))\s+(\w+=|$)""",
    """\Wext_targetResources_0__displayName=(|({target}.+?))\s+(\w+=|$)""",
    """\WdestinationServiceName=(|({event_subtype}.+?))\s+(\w+=|$)""",
    """\Wext_category=(|({additional_info}.+?))\s+(\w+=|$)""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]+)"""",
    """"userPrincipalName":"({user_email}[^"@\s]+@[^"@\s]+)"""",
  ]
}
```