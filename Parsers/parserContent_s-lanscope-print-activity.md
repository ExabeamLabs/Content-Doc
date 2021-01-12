#### Parser Content
```Java
{
Name = s-lanscope-print-activity
  Vendor = LanScope
  Product = LanScope Cat
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ ""","プリントログ",""", ""","ドキュメントの印刷",""" ]
  Fields = [
    ""","(|({host}[^"]+))","(|({user}[^"]+))","({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)","プリントログ"""",
    """ドキュメントの印刷",("[^"]*",){7}"(|({printer_name}[^"]+))","[^"]*","(|({num_pages}\d+))","[^"]*","(|({dest_ip}[^"]+))",""",
  ]
}
```