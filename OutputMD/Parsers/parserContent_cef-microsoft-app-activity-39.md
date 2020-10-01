#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-39
  Product = Microsoft Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"Operation":"MoveToDeletedItems"""" ]
  Fields = ${MSParserTemplates.cef-microsoft-app-activity.Fields} [
    """"ParentFolder":.+?"Path":"\\*({object}[^"]+)"""",
    """"DestFolder":.+?"Path":"\\*({object}[^"]+)"""",
    """\Wfname=\s*({object}.+?)\s+(\w+=|$)""",
    """"target_object":"({object}[^"]+?)""""
    """sourceServiceName=({app}.+?)\s+(\w+=|$)""",
    """requestMethod=({app}.+?)\s+(\w+=|$)""",   
    """ext_userAgent_name=({resource}.+?)\s+(\w+=|$)""",
    """({activity}MoveToDeletedItems)""" 
  ]
}
```