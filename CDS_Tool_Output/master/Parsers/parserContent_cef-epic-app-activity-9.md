#### Parser Content
```Java
{
Name = cef-epic-app-activity-9
  Conditions = [ """CEF:""", """|Epic|Security-SIEM|""", """|CONTEXTCHANGE|""" ]
  Fields = ${EpicParserTemplates.cef-epic-app-activity.Fields} [
    """PREVDEPARTMENT=({object}.+?)\s+(\w+=|$)""",
    """NEWDEPARTMENT=({resource}.+?)\s+(\w+=|$)""",
  ]
}
```