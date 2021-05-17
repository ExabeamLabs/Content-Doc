#### Parser Content
```Java
{
Name = accelion-kite-app-reset-password
  DataType = "account-password-reset"
  Conditions = [ """url_host""", """app_host""", """description""", """reset_password""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}user"{1,20}.*?name"{1,20}:\s"{1,20}({target_user}[^"]{1,2000})""",
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}({additional_info}.*?)""{0,20}\,\s"{1,20}successful"""
    ]
}
```