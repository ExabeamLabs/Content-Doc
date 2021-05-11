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
    """\ssuser=([^\s]+\/)?({user_email}[^\s@]+@[^\s@]+)\s{1,100}(\w+=|$)""",
    """"operation_detail"\s{0,100}:\s{0,100}"({additional_info}[^"]+)""",
    """"action"\s{0,100}:\s{0,100}"({activity}[^"]+)"""",
    """"category_type"\s{0,100}:\s{0,100}"({object_type}[^"]+)"""",
    """"operation_detail"\s{0,100}:\s{0,100}".*?\s{1,100}({object}[^\s@"]+@[^\s@"]+)\s{1,100}"""
  ]
}
```