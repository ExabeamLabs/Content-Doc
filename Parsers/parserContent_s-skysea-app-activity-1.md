#### Parser Content
```Java
{
Name = s-skysea-app-activity-1
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,クリップボード,""" ]
  Fields = [
    """({host}[\w\-.]+),\d+,({src_host}[\w\-.]+),({src_ip}[A-Fa-f:\d.]+),[^,]*,({user}[^\s,]+),({user_fullname}[^,\(\（]+(\（[^\）,]+\）)?)[^,]*,({time}\d+\/\d+\/\d+ \d+:\d+:\d+),({activity}[^,]+),([^,]*,){22}\s*($|(|({object}[^,]+?)\s*,))""",
    """,クリップボード,([^,]*,){22}(\s*$|"+\s*({object}[^"]+?)\s*"+)""",
    """({app}skysea)""",
  ]
}
```