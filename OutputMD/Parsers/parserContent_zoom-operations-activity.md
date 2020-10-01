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
    """exabeam_host=({host}[\w.\-]+)""",
    """\d+-\d+-\d+T\d+:\d+:\d+\.\d+\w ({host}[\w\-.]+) Skyformation""",
    """\WdestinationServiceName=({app}.+?)(\s+\w+=|\s*$)""",
    """\Wend=({time}\d+)""",
    """\ssuser=([^\s]+\/)?({user_email}[^\s@]+@[^\s@]+)\s+(\w+=|$)""",
    """"operation_detail"\s*:\s*"({additional_info}[^"]+)""",
    """"action"\s*:\s*"({activity}[^"]+)"""",
    """"category_type"\s*:\s*"({object_type}[^"]+)"""",
    """"operation_detail"\s*:\s*".*?\s+({object}[^\s@"]+@[^\s@"]+)\s+"""
  ]
}
```