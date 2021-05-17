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
    ""","(|({host}[^"]{1,2000}))","(|({user}[^"]{1,2000}))","({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)","プリントログ"""",
    """ドキュメントの印刷",("[^"]{0,2000}",){7}"(|({printer_name}[^"]{1,2000}))","[^"]{0,2000}","(|({num_pages}\d{1,100}))","[^"]{0,2000}","(|({dest_ip}[^"]{1,2000}))",""",
  ]
}
```