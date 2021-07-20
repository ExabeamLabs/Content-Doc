#### Parser Content
```Java
{
Name = lexmark-print-activity
  Vendor = Lexmark
  Product = Lexmark
  Lms = Direct
  DataType = "print-activity"
  TimeFormat = "epoch"
  Conditions = [ """|Lexmark|Print Release|""", """|Print Job|"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\sstart=(?:|({time}\d{1,100}))(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssuid=(?:|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sduid=(?:|({account}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """src=(?:|({host}.+?))\s{1,100}name=CEF""",
    """\scn1=(?:|({num_pages}\d{1,100}))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sact=(?:|({event_code}\w+))(\s{1,100}\w+=|\s{0,100}$)""",
    """\scs5=(?:|({printer_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdhost=(?:|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdst=(?:|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc=(?:|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sfname=(?:|({object}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```