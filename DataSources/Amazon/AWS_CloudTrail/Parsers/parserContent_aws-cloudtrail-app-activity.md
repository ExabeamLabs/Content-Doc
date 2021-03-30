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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"+timestamp"+:"+({time}[^"]+)"""",
    """({host}\d+),""",
    """"+project_id"+:"+({project_id}[^"]+)"""",
    """"+logName"+:"+({logName}[^"]+)"""",
    """"+eventName\\?"+:\\?"+({activity}[^"\\]+)\\?"""",
    """"+eventSource\\\?"+:\\?"+({service}[^"\\]+)\\?"""",
    """"+eventType\\?"+:\\?"+({app}[^"\\]+)\\?"""",
    """"+accountId\\?"+:\\?"+({account_id}[^"\\]+)\\?"""",
    """"+eventID\\?"+:\\?"+({event_log_id}[^"\\]+)\\?"""",
    """"+sourceIPAddress\\?"+:\\?"+(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"\\]+))\\?"""",
    """"+userAgent\\?"+:\\?"+({user_agent}[^"\\]+)\\?"""",
    """userIdentity.+?"+type\\?"+:\\?"+({account_type}[^"\\]+)\\?"""",
    """"+userName\\?"+:\\?"+({user}[^"\\]+)\\?"""",
    """bucketName\\?"+:\\?"+({object}[^\\]+)\\?""""
    """assumed-role({role}.+?)\\""""
  ]

}
```