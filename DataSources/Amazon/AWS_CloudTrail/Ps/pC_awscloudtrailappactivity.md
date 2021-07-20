#### Parser Content
```Java
{
Name = aws-cloudtrail-app-activity
  Vendor = Amazon
  Product = AWS CloudTrail
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """AwsApiCall\""" , """logSource"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"{1,20}timestamp"{1,20}:"{1,20}({time}[^"]{1,2000})"""",
    """({host}\d{1,100}),""",
    """"{1,20}project_id"{1,20}:"{1,20}({project_id}[^"]{1,2000})"""",
    """"{1,20}logName"{1,20}:"{1,20}({logName}[^"]{1,2000})"""",
    """"{1,20}eventName\\?"{1,20}:\\?"{1,20}({activity}[^"\\]{1,2000})\\?"""",
    """"{1,20}eventSource\\\?"{1,20}:\\?"{1,20}({service}[^"\\]{1,2000})\\?"""",
    """"{1,20}eventType\\?"{1,20}:\\?"{1,20}({app}[^"\\]{1,2000})\\?"""",
    """"{1,20}accountId\\?"{1,20}:\\?"{1,20}({account_id}[^"\\]{1,2000})\\?"""",
    """"{1,20}eventID\\?"{1,20}:\\?"{1,20}({event_log_id}[^"\\]{1,2000})\\?"""",
    """"{1,20}sourceIPAddress\\?"{1,20}:\\?"{1,20}(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"\\]{1,2000}))\\?"""",
    """"{1,20}userAgent\\?"{1,20}:\\?"{1,20}({user_agent}[^"\\]{1,2000})\\?"""",
    """userIdentity.+?"{1,20}type\\?"{1,20}:\\?"{1,20}({account_type}[^"\\]{1,2000})\\?"""",
    """"{1,20}userName\\?"{1,20}:\\?"{1,20}({user}[^"\\]{1,2000})\\?"""",
    """bucketName\\?"{1,20}:\\?"{1,20}({object}[^\\]{1,2000})\\?""""
    """assumed-role({role}.+?)\\""""
  ]

}
```