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
    """({host}[\w\-.]{1,2000}),\d{1,100},({src_host}[\w\-.]{1,2000}),({src_ip}[A-Fa-f:\d.]{1,2000}),[^,]{0,2000},({user}[^\s,]{1,2000}),({user_fullname}[^,\(\（]{1,2000}(\（[^\）,]{1,2000}\）)?)[^,]{0,2000},({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}),({activity}[^,]{1,2000}),([^,]{0,2000},){22}\s{0,100}($|(|({object}[^,]{1,2000}?)\s{0,100},))""",
    """,クリップボード,([^,]{0,2000},){22}(\s{0,100}$|"{1,20}\s{0,100}({object}[^"]{1,2000}?)\s{0,100}"{1,20})""",
    """({app}skysea)""",
  ]
}
```