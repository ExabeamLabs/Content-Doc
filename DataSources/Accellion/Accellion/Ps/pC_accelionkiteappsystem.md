#### Parser Content
```Java
{
Name = accelion-kite-app-system
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """System""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}({additional_info}.*?)""{0,20}\,\s"{1,20}successful"""
    ]
   DupFields = [ "additional_info->activity" ]
}
```