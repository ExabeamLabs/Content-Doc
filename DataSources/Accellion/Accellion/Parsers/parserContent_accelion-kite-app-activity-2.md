#### Parser Content
```Java
{
Name = accelion-kite-app-activity-2
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """changed_draft""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}mail.+attachments"{1,20}:([^,]+,\s{0,100}"{1,20}name"{1,20}:\s{0,100}"{1,20})({attachment}[^"]+)"{1,20}""",
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}({additional_info}.*?)""{0,20}\,\s"{1,20}successful"""
    ]
    DupFields = [ "accesses->activity" ]
}
```