#### Parser Content
```Java
{
Name = accelion-kite-app-activity-email-alert
  DataType = "dlp-email-alert"
  Conditions = [ """url_host""", """app_host""", """description""", """send_mail""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}subject"{1,20}:\s{0,100}"{1,20}({subject}[^"]{1,2000})"{1,20}""",
    """\sTo:\s{0,100}({recipients}.+?)\s{0,100}with files \[({attachments}.+?)\]""",
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}({additional_info}.*?)""{0,20}\,\s"{1,20}successful"""
        ]
    DupFields = [ "user_email->sender" ]
}
```