#### Parser Content
```Java
{
Name = outlook-exchange-app-activity-9
  Conditions = ["""Office365""",""" COMMAND=SendAs ""","""USERKEY=""","""ORGANIZATIONNAME=""","""SENDASUSER=""" ]
  Fields = ${MSParserTemplates.outlook-exchange-app-activity.Fields} [
    """SENDASUSER=({target}[^\s]+)""",
  ]
  DupFields = [ "subject->object", "attachments->additional_info" ]
}
```