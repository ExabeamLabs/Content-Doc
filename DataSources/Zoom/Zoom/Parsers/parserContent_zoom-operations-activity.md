#### Parser Content
```Java
{
Name = zoom-operations-activity
  Vendor = Zoom
  Product = Zoom
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """|Skyformation|""", """dproc=Operation Logs""", """destinationServiceName=Zoom""" ]
  Fields = [
    """\WdestinationServiceName=({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wend=({time}\d{1,100})""",
    """\ssuser=([^\s]{1,2000}\/)?({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """"operation_detail"\s{0,100}:\s{0,100}"({additional_info}[^"]{1,2000})""",
    """"action"\s{0,100}:\s{0,100}"({activity}[^"]{1,2000})"""",
    """"category_type"\s{0,100}:\s{0,100}"({object_type}[^"]{1,2000})"""",
    """"operation_detail"\s{0,100}:\s{0,100}".*?\s{1,100}({object}[^\s@"]{1,2000}@[^\s@"]{1,2000})\s{1,100}"""
  ]
}
```