#### Parser Content
```Java
{
Name = s-aws-s3-cloud-storage-activity
  Vendor = Amazon
  Product = AWS CloudTrail
  Lms = Splunk
  DataType = "cloud-storage-activity"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
  Conditions = [ """"aws:s3:accesslogs"""", """sourcetype"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(gcs-topic|({host}\S+))""",
    """({bucket}\S{1,2000})\s\[({time}\d\d\/\w\w\w\/\d\d\d\d:\d\d:\d\d:\d\d\s[+-]\d\d\d\d)\]\s(-|({src_ip}[A-Fa-f\d:.]{1,2000}))\s\S{1,2000}\s\S{1,2000}\s(-|({activity}\S{1,2000}))\s\S{1,2000}\s\S{1,2000}\s\S{1,2000}\s\S{1,2000}\s\S{1,2000}\s(-|({failure_reason}\S{1,2000}))\s\S{1,2000}\s\S{1,2000}\s\S{1,2000}\s\S{1,2000}\s\S{1,2000}\s((\\\\)?"(-|({user_agent}[^"\\]{1,2000})))?""",
    """\[(\d\d\/\w{1,4}\/\d\d\d\d:\d\d:\d\d:\d\d\s[+-]\d\d\d\d)\](\s\S{1,2000}){15}\s[\\"]*[^"]+"(\s\S{1,2000}){5}\s({service}[\w\-.]{1,2000})""",
  ]
  DupFields = [ "service->host" ]


}
```