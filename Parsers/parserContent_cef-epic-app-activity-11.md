#### Parser Content
```Java
{
Name = cef-epic-app-activity-11
  Product = Epic SIEM
  Conditions = [ """CEF:""", """|Epic|Security-SIEM|""", """|ED_BROWSER_EXTERNAL_PAGE|""" ]
  Fields = ${EpicParserTemplates.cef-epic-app-activity.Fields} [
    """PAGE=({object}.+?)\s+(\w+=|$)""",
  ]
}
```