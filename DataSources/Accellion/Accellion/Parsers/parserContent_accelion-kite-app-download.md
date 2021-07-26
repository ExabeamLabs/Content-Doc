#### Parser Content
```Java
{
Name = accelion-kite-app-download
  DataType = "file-operations"
  Conditions = [ """url_host""", """app_host""", """description""", """download_email_zip""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """node_ip.*?name"{1,20}:\s{0,100}"{1,20}({file}[^"]{1,2000})"{1,20}""",
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}({additional_info}.*?)""{0,20}\,\s"{1,20}successful"""
    ]
}
```