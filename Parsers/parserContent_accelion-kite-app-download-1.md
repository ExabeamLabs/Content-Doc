#### Parser Content
```Java
{
Name = accelion-kite-app-download-1
  DataType = "file-operations"
  Conditions = [ """url_host""", """app_host""", """description""", """download_email""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+attachments.*?,\s*"+name"+:\s*"+({file}[^"]+)"+([\w\s,":\/.]+)\}\,\s*\{.*?,\s*"+name"+:\s*"+({file_1}[^"]+)"+([\w\s,":\/.]+)\}
```