#### Parser Content
```Java
{
Name = cef-duo-app-activity-1
  Vendor = Cisco
  Product = Duo Access Security
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """API (IAM UI Admin API)""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({time}\d{4}-\d{2}-\d{2}\s(\d{2}:){2}\d{2})""",
    """API \(({app}IAM UI Admin API)\)\|({user}[^\|]{1,2000})\|({activity}[^\|]{1,2000})\|""",
    """"email":\s{0,100}"({user_email}[^@]{1,2000}@[^.]{1,2000}\.\w+?)"""",
    """"type":\s{0,100}"({object}[^"]{1,2000})""""
  ]
  DupFields = ["object->device"]


}
```