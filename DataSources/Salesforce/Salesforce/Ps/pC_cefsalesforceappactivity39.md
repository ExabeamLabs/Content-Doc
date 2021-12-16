#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-39
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|user-locked-out|""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",  
    """destinationServiceName =({host}.+?)\s{0,100}(\w+=|$)""",
    """LoginTime\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """suser=([^\s\\\=]{1,2000}\\\=)?({user_email}[^\\\=\s;]{1,2000})""",
    """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """SourceIp\\=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """dvchost=({src_host}[\w\-.]{1,2000})""",
    """sourceDnsDomain=({dest_host}[\w\-.]{1,2000})""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """\Wduser=({object}.+?)\s{1,100}(\w+=|$)""",
    """({app}Sales Cloud)"""
  ]
  DupFields = [ "user_email->user" ]


}
```