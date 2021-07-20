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
          """\Wcat=\s{0,100}Devices:\s{0,100}({activity}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
          """\Wact=({action}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
          """\Wmsg=({activity_details}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
          """\Wrt=({time}\d{1,100})""",
          """\Wsuser=(({domain}[^\\]{1,2000})\\+)?({user}[^\\]{1,2000})(\s{1,100}\w+=|\s{0,100}$)""",
          """\Wsntdom=({domain}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
          """\Wshost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
          """\WfilePath=({file_path}.*?[\\\/]{0,2000}({file_name}[^\\\/]{0,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
          """\Wfsize=({bytes}\d{1,100})""",
        ]
    }
```