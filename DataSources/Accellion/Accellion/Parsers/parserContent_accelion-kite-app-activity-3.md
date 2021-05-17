#### Parser Content
```Java
{
Name = accelion-kite-app-activity-3
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """add_user""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}({additional_info}[^"]{1,2000})"""
    ]
   DupFields = [ "additional_info->activity" ]
}
```