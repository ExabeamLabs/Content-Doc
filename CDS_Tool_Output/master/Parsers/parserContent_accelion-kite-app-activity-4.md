#### Parser Content
```Java
{
Name = accelion-kite-app-activity-4
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """created_draft""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+mail"+.*?subject"+:\s*"+({subject}[^"]+)"+\}.*?attachments"+.*?:\s*\[(.*?name"+:\s*"+({file_name}[^"]+))?.*?user_ip""",
    """"+description"+:\s+"+({additional_info}.*?)""*\,\s"+successful"""
    ]
    DupFields = [ "accesses->activity" ]
}
```