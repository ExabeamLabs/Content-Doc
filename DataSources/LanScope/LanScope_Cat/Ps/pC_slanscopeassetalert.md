#### Parser Content
```Java
{
Name = s-lanscope-asset-alert
  Vendor = LanScope
  Product = LanScope Cat
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ ""","資産アラームログ",""" ]
  Fields = [
    ""","(|({host}[^"]{1,2000}))","(|({user}[^"]{1,2000}))","({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)",("[^"]{0,2000}",){7}"(|({activity}[^"\-]{1,2000}?)\s{0,100}\-\s{0,100}({object}[^"]{1,2000}))","""
  ]
}
```