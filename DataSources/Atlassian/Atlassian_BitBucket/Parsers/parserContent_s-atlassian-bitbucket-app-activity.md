#### Parser Content
```Java
{
Name = s-atlassian-bitbucket-app-activity
  Vendor = Atlassian
  Product = Atlassian BitBucket
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """ | SSH - git""" ]
  Fields = [
    """([^\|]*\|){4}\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """([^\|]*\|){0}\s{0,100}({src_ip}[A-Fa-f:\d.]+)\s{0,100}\|""",
    """([^\|]*\|){3}\s{0,100}({user}[^\s\|]+)""",
    """([^\|]*\|){5}\s{0,100}({action}[^\|]+?)\s{0,100}\|""",
    """([^\|]*\|){5}\s{0,100}SSH - ({activity}[^\|\']+)\s\'({object}[^\|\']+)\'""",
    """([^\|]*\|){10}\s{0,100}({additional_info}[^\|]+?)\s{0,100}\|""",
  ]
}
```