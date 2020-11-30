#### Parser Content
```Java
{
Name = cef-microsoft-graph-activity-3
  DataType = "failed-app-login"
  Conditions = [ """"event-name":""", """"src-endpoint":"mcas-activities"""", """"activityResult":""", """event-name":"login-failed""" ]
  Fields = ${MSParserTemplates.cef-o365-app-login-1.Fields} [
    """activityResult":[^}]+?message":"({failure_reason}[^"]+)""",  
  ]
}
```