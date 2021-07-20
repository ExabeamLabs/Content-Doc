#### Parser Content
```Java
{
Name = accelion-kite-app-activity-4
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """created_draft""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}mail"{1,20}.*?subject"{1,20}:\s{0,100}"{1,20}({subject}[^"]{1,2000})"{1,20}\}.*?attachments"{1,20}.*?:\s{0,100}\[(.*?name"{1,20}:\s{0,100}"{1,20}({file_name}[^"]{1,2000}))?.*?user_ip""",
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}({additional_info}.*?)""{0,20}\,\s"{1,20}successful"""
    ]
    DupFields = [ "accesses->activity" ]
}
```