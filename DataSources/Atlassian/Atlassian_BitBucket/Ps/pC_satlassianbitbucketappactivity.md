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
    """([^\|]{0,2000}\|){4}\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """([^\|]{0,2000}\|){0}\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})\s{0,100}\|""",
    """([^\|]{0,2000}\|){3}\s{0,100}({user}[^\s\|]{1,2000})""",
    """([^\|]{0,2000}\|){5}\s{0,100}({action}[^\|]{1,2000}?)\s{0,100}\|""",
    """([^\|]{0,2000}\|){5}\s{0,100}SSH - ({activity}[^\|\']{1,2000})\s\'({object}[^\|\']{1,2000})\'""",
    """([^\|]{0,2000}\|){10}\s{0,100}({additional_info}[^\|]{1,2000}?)\s{0,100}\|""",
  ]
}
```