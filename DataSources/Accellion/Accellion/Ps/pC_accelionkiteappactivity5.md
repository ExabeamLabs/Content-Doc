#### Parser Content
```Java
{
Name = accelion-kite-app-activity-5
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """view_mail""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}subject"{1,20}:\s{0,100}"{1,20}({subject}[^"]{1,2000})"{1,20}""",
    """To:\s{1,100}({recipients}[^"]{1,2000})"{1,20}""",
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}({additional_info}.*?)""{0,20}\,\s"{1,20}successful"""
    ]
    DupFields = [ "additional_info->activity" ]
}
```