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

  {
    Name = cef-mcafee-usb-activity
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Direct
    DataType = "usb-activity"
    TimeFormat = "epoch"
    Conditions = [ """|McAfee|Host Data Loss Prevention|""", """|DEVICE_PLUG|""" ]
    Fields = [
	"""\srt=({time}\d+)""",
	"""exabeam_host=({host}[^\s]+)""",
	"""\sdhost=({dest_host}.+?)\s\w+=""",
	"""\sdst=({dest_ip}.+?)\s\w+=""",
	"""\sduser=(({domain}[^\\]+)\\+)?({user}[^=]+)\s\w+=""",
	"""\scs4=([^,]*,){4}\s*({device_id}.+?)(\s\w+=|&\d|,)""",
	"""\scs4=([^,]*,)\s*({device_type}[^,]+)""",
	"""\scs4=([^,]*,\s*){2}({activity_details}[^,]+)""",
	"""\|McAfee\|Host Data Loss Prevention\|([^|]*\|)({activity}[^|]+)""",
    ]
  }
```