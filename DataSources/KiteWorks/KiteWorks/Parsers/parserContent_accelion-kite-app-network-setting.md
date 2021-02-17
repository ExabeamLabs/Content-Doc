#### Parser Content
```Java
{
Name = accelion-kite-app-network-setting
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """network_settings""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+proxy_ip\\"+.+to\s+\\"+({proxy_ip}[^\/]+)""",
    """"+description"+:\s+"+({additional_info}.*?)""*\,\s"+successful"""
    ]
   DupFields = [ "additional_info->activity" ]
}
```