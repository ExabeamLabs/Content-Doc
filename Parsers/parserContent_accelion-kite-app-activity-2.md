#### Parser Content
```Java
{
Name = accelion-kite-app-activity-2
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """changed_draft""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+mail.+attachments"+:([^,]+,\s*"+name"+:\s*"+)({attachment}[^"]+)"+""",
    """"+description"+:\s+"+({additional_info}.*?)""*\,\s"+successful"""
    ]
    DupFields = [ "accesses->activity" ]
}
```