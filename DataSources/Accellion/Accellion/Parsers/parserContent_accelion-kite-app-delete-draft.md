#### Parser Content
```Java
{
Name = accelion-kite-app-delete-draft
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """delete_draft""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+description"+:\s+"+({additional_info}.*?):"""
    ]
}
```