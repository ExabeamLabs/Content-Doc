#### Parser Content
```Java
{
Name = syslog-mcafee-epo-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Direct
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd H:mm:ss a"
    Conditions = [ """ McAfee ePolicy Orchestrator ""","""ePOEvents""" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d\s{1,100}\d{1,2}:\d\d:\d\d (AM|PM|am|pm))(,[^,]{0,2000}){5}ePOEvents""",
      """ePOEvents([^,]{0,2000}
```