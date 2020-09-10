#### Parser Content
```Java
{
Name = accelion-kite-app-activity-email-alert
  DataType = "dlp-email-alert"
  Conditions = [ """url_host""", """app_host""", """description""", """send_mail""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+subject"+:\s*"+({subject}[^"]+)"+""",
    """\sTo:\s*({recipients}.+?)\s*with files \[({attachments}.+?)\]""",
    """"+description"+:\s+"+({additional_info}.*?)""*\,\s"+successful"""
        ]
    DupFields = [ "user_email->sender" ]
}
```