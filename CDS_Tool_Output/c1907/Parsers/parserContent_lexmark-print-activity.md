#### Parser Content
```Java
{
Name = lexmark-print-activity
  Vendor = Lexmark
  Lms = Direct
  DataType = "print-activity"
  TimeFormat = "epoch"
  Conditions = [ """|Lexmark|Print Release|""", """|Print Job|"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\sstart=(?:|({time}\d+))(\s+\w+=|\s*$)""",
    """\ssuid=(?:|({user}.+?))(\s+\w+=|\s*$)""",
    """\sduid=(?:|({account}.+?))(\s+\w+=|\s*$)""",
    """src=(?:|({host}.+?))\s+name=CEF""",
    """\scn1=(?:|({num_pages}\d+))(\s+\w+=|\s*$)""",
    """\sact=(?:|({event_code}\w+))(\s+\w+=|\s*$)""",
    """\scs5=(?:|({printer_name}.+?))(\s+\w+=|\s*$)""",
    """\sdhost=(?:|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\sdst=(?:|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))(\s+\w+=|\s*$)""",
    """\ssrc=(?:|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))(\s+\w+=|\s*$)""",
    """\sfname=(?:|({object}.+?))(\s+\w+=|\s*$)""",
  ]
}
```