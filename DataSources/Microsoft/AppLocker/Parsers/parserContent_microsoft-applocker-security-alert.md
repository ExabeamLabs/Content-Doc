#### Parser Content
```Java
{
Name = microsoft-applocker-security-alert
  Vendor = Microsoft
  Product = AppLocker
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<Channel>Microsoft-Windows-AppLocker""", """<PolicyName>""", """<Message>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """<Computer>({host}.+?)</Computer>""",
    """<Data Name='User'>(({domain}[^\\<]{1,2000}?)\\)?({user}.+?)</Data>""",
    """<Security UserID='({user_sid}.+?)'/>""",
    """<Level>({alert_severity}[^"<]{1,2000})""",
    """<FilePath>({malware_url}[^"<]{1,2000})""",
    """<PolicyName>({alert_type}[^"<]{1,2000})""",
    """<PolicyName>({alert_name}[^"<]{1,2000})""",
    """<Message>({additional_info}[^"<]{1,2000})""",
    """<FileHash>({md5}[^"<]{1,2000})""",
  ]
  DupFields = ["malware_url->process_name"]
}
```