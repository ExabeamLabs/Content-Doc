#### Parser Content
```Java
{
Name = cef-mcafee-usb-insert
        Vendor = McAfee
        Product = McAfee Endpoint Security
        Lms = ArcSight
        DataType = "usb-activity"
        TimeFormat = "epoch"
        Conditions = [ """|McAfee|DLPE|""", """ Device Plug|""" ]
        Fields = [
          """\Wcat=\s*Devices:\s*({activity}.+?)(\s+\w+=|\s*$)""",
          """\Wact=({action}.+?)(\s+\w+=|\s*$)""",
          """\Wmsg=({activity_details}.+?)(\s+\w+=|\s*$)""",
          """\Wrt=({time}\d+)""",
          """\Wsuser=(({domain}[^\\]+)\\+)?({user}[^\\]+)(\s+\w+=|\s*$)""",
          """\Wsntdom=({domain}.+?)(\s+\w+=|\s*$)""",
          """\Wshost=({host}.+?)(\s+\w+=|\s*$)""",
          """\WfilePath=({file_path}.*?[\\\/]*({file_name}[^\\\/]*?))(\s+\w+=|\s*$)""",
          """\Wfsize=({bytes}\d+)""",
        ]
    }
```