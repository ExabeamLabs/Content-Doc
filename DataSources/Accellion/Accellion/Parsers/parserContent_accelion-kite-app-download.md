#### Parser Content
```Java
{
Name = accelion-kite-app-download
  DataType = "file-operations"
  Conditions = [ """url_host""", """app_host""", """description""", """download_email_zip""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """node_ip.*?name"+:\s*"+({file}[^"]+)"+""",
    """"+description"+:\s+"+({additional_info}.*?)""*\,\s"+successful"""
    ]
}
```