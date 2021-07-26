#### Parser Content
```Java
{
Name = accelion-kite-app-delete-draft
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """delete_draft""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}({additional_info}.*?):"""
    ]
}
```