#### Parser Content
```Java
{
Name = q-kiteworks-email-out
  Product = Kiteworks
  Conditions = [ """Activity: Sent e-mail""", """with files""" ]
}

${KiteWorksParserTemplates.q-kiteworks-email}{
  Name = q-kiteworks-email-out-1
  Product = Kiteworks
  Conditions = [ """Activity: Created draft""", """with files""" ]
}

{
  Name = accelion-dlp-alert
  Vendor = Accelion
  Product = Kiteworks
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """subject=HTTP incident""", """, incident-id=""", """, Sender Email=""", """, recipient-email1=""" ]
  Fields = [
    """, incident-reported-on=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+(\+|\-)\d+)""",
    """policy-desc=({alert_name}[^,]+)""",
    """, Employee Code=({user}[^,]+)""",
    """, Sender Email=({user_email}[^,@]+@[^,@]+)""",
    """exabeam_attachment_name1=({file_name}\S+)""",
    """exabeam_attachment_size1=({bytes}\S+)""",
    """, attachment-name1=({file_name}[^,]+)""",
    """, attachment-size1=({bytes}[^,]+)""",
    """, policy-name=({alert_type}[^,]+)""",
    """, incident-id=({alert_id}[^,]+)""",
    """, recipient-email1=({additional_info}[^,]+)""",
    """^.*?, First Name=({user_firstname}[^,]+)""",
    """^.*?, Last Name=({user_lastname}[^,]+)""",
    """, protocol=({protocol}[^,]+)""",
    """, incident-severity=({alert_severity}[^,]+)""",
    """, monitor-host=({host}[^,]+)""",
    """, recipient-url1=({malware_url}[^,]+)""",
    """, mail_status=({outcome}[^,]+)""",
  ]
}
```