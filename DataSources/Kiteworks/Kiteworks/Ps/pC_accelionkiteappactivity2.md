#### Parser Content
```Java
{
Name = accelion-kite-app-activity-2
  Product = Kiteworks
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """changed_draft""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}mail.+attachments"{1,20}:([^,]{1,2000}
}
```