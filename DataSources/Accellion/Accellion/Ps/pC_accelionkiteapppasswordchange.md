#### Parser Content
```Java
{
Name = accelion-kite-app-password-change
  DataType = "password-change"
  Conditions = [ """url_host""", """app_host""", """description""", """update_password""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """\{"{1,20}user([^,]{1,2000}
```