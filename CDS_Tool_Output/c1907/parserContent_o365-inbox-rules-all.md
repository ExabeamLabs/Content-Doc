#### Parser Content
```Java
{
Name = o365-inbox-rules-all
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""New-InboxRule""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """"Name":"ForwardTo".+?"Value":"(?:smtp:)?({target}[^"]+)""""
    """"ResultStatus":"({outcome}[^"]+)"""",
    """"ClientIP":"({src_ip}[^:]+):""",
    """({activity}New-InboxRule)"""
    """cs1=(\[\{"additional-properties"\:)?\{"({activity}[^"]+)""",
    """msg=({additional_info}.+?)\s\w+=""",
    """"Value":"(?:smtp:)?.+?@({target_domain}[^"]+)"""",
    """UserId":"({user}.+?@({user_domain}[^"]+).+?)""",
    """destinationServiceName=({app}.+?)\s*filePath""",
    """({app}Office 365)"""
  ]
}

{
  Name = o365-inbox-rules-all-2
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""Operation":"Set-InboxRule""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """Forward.+?Value":"(smtp:)?({target}[^"]+@({target_domain}[^"]+))""""
    """"ResultStatus":"({outcome}[^"]+)"""",
    """"ClientIP":"({src_ip}[^:]+):""",
    """({activity}Set-Mailbox)""",
    """cs1=(\[\{"additional-properties"\:)?\{"({activity}[^"]+)""",
    """msg=({additional_info}.+?)\s\w+=""",
    """"Value":"(?:smtp:)?.+?@({target_domain}[^"]+)"""",
    """UserId":"({user_email}[^"\\]+@({user_domain}[^"]+)[^"]+)"""",
    """UserId":"(\\.+)?\/({user_fullname}[^,\\"]+)\\"\s*on behalf""",
    """UserId":"(\\.+)?\/({user_lastname}[^,]+),\s*({user_firstname}[^\\"]+)\\"\s*on behalf""",
    """UserId":"({user_email}[^"\\]+@({user_domain}[^"]+)[^"]+)"""",   
    """destinationServiceName=({app}.+?)\s*filePath"""
    """({app}Office 365)"""
  ]
}

{
  Name = o365-security-alert
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """AlertTriggered""", """AlertType=""", """AlertId""", """destinationServiceName=Office 365"""]
  Fields = [
   """"(ts|CreationTime)":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
   """exabeam_host=({host}[^\s]+)""",
   """"f3u":"({user_email}[^"]+)""",
   """"ad":"({additional_info}[^"]+)""",
   """"(Name|an)":"({alert_name}[^"]+)""",
   """"AlertId":"({alert_id}[^"]+)""""
   """"(sev|Severity)":"({alert_severity}[^"]+)""",
   """"AlertType":"({alert_type}[^"]+)""""
  ]
}
```