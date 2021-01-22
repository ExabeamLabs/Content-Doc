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
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """<Computer>({host}.+?)</Computer>""",
    """<Data Name='User'>(({domain}[^\\<]+?)\\)?({user}.+?)</Data>""",
    """<Security UserID='({user_sid}.+?)'/>""",
    """<Level>({alert_severity}[^"<]+)""",
    """<FilePath>({malware_url}[^"<]+)""",
    """<PolicyName>({alert_type}[^"<]+)""",
    """<PolicyName>({alert_name}[^"<]+)""",
    """<Message>({additional_info}[^"<]+)""",
    """<FileHash>({md5}[^"<]+)""",
  ]
}
```