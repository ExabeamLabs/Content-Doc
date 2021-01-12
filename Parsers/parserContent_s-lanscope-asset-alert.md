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
    ""","(|({host}[^"]+))","(|({user}[^"]+))","({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)",("[^"]*",){7}"(|({activity}[^"\-]+?)\s*\-\s*({object}[^"]+))","""
  ]
}
```