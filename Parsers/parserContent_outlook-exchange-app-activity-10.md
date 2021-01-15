#### Parser Content
```Java
{
Name = outlook-exchange-app-activity-10
  Conditions = [ """Office365""",""" COMMAND=SendOnBehalf ""","""USERKEY=""","""ORGANIZATIONNAME=""","""SENDONBEHALFOFUSER=""" ]
  Fields = ${MSParserTemplates.outlook-exchange-app-activity.Fields} [ 
    """SENDONBEHALFOFUSER=({target}[^=]+?)(\s|$)"""
  ]
  DupFields = [ "subject->object", "attachments->additional_info" ]
}
```