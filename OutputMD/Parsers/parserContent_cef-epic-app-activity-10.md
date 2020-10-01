#### Parser Content
```Java
{
Name = cef-epic-app-activity-10
  Product = Epic SIEM
  Conditions = [ """CEF:""", """|Epic|Security-SIEM|""", """|E_HIDDEN_SOURCE_ACCESS_GRANTED|""" ]
  Fields = ${EpicParserTemplates.cef-epic-app-activity.Fields} [
    """PRTCTDSRCUSERID=({user}[^\s]+)""",
  ]
}
```