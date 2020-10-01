#### Parser Content
```Java
{
Name = s-atlassian-bitbucket-app-activity
  Vendor = Atlassian BitBucket
  Product = Atlassian BitBucket
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """ | SSH - git""" ]
  Fields = [
    """([^\|]*\|){4}\s*({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """([^\|]*\|){0}\s*({src_ip}[A-Fa-f:\d.]+)\s*\|""",
    """([^\|]*\|){3}\s*({user}[^\s\|]+)""",
    """([^\|]*\|){5}\s*({action}[^\|]+?)\s*\|""",
    """([^\|]*\|){5}\s*SSH - ({activity}[^\|\']+)\s\'({object}[^\|\']+)\'""",
    """([^\|]*\|){10}\s*({additional_info}[^\|]+?)\s*\|""",
  ]
}
```