#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-39
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Skyformation|SkyFormation Cloud Apps Security|""", """|user-locked-out|""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",  
    """destinationServiceName=({host}.+?)\s{0,100}(\w+=|$)""",
    """LoginTime\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """suser=([^\s\\\=]+\\\=)?({user_email}[^\\\=\s;]+)""",
    """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
    """SourceIp\\=({src_ip}[A-Fa-f:\d.]+)""",
    """dvchost=({src_host}[\w\-.]+)""",
    """sourceDnsDomain=({dest_host}[\w\-.]+)""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """\Wduser=({object}.+?)\s{1,100}(\w+=|$)""",
    """({app}Sales Cloud)"""
  ]
  DupFields = [ "user_email->user" ]
}
```