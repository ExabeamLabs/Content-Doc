#### Parser Content
```Java
{
Name = accelion-dlp-alert
  Vendor = Accellion
  Product = Kiteworks
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """subject=HTTP incident""", """, incident-id=""", """, Sender Email=""", """, recipient-email1=""" ]
  Fields = [
    """, incident-reported-on=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d{1,100})""",
    """policy-desc=({alert_name}[^,]{1,2000})""",
    """, Employee Code=({user}[^,]{1,2000})""",
    """, Sender Email=({user_email}[^,@]{1,2000}@[^,@]{1,2000})""",
    """exabeam_attachment_name1=({file_name}\S+)""",
    """exabeam_attachment_size1=({bytes}\S+)""",
    """, attachment-name1=({file_name}[^,]{1,2000})""",
    """, attachment-size1=({bytes}[^,]{1,2000})""",
    """, policy-name=({alert_type}[^,]{1,2000})""",
    """, incident-id=({alert_id}[^,]{1,2000})""",
    """, recipient-email1=({additional_info}[^,]{1,2000})""",
    """^.*?, First Name=({user_firstname}[^,]{1,2000})""",
    """^.*?, Last Name=({user_lastname}[^,]{1,2000})""",
    """, protocol=({protocol}[^,]{1,2000})""",
    """, incident-severity=({alert_severity}[^,]{1,2000})""",
    """, monitor-host=({host}[^,]{1,2000})""",
    """, recipient-url1=({malware_url}[^,]{1,2000})""",
    """, mail_status=({outcome}[^,]{1,2000})""",
  ]
}
```