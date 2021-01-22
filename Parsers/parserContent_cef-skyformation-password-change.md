#### Parser Content
```Java
{
Name = cef-skyformation-password-change
  Vendor = Cloud Application
  Lms = ArcSight
  DataType = "password-change"
  TimeFormat = "epoch"
  Conditions = [ """|Skyformation|""", """"Action":"Password Changed"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\WdestinationServiceName=({app}.+?)(\s+\w+=|\s*$)""",
    """\Wend=({time}\d+)""",
    """\Wdproc=({process_name}.+?)(\s+\w+=|\s*$)""",
    """\Wfname=(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\Wmsg=({additional_info}.+?)(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsuser=({user_email}[^@\s]+@[^@\s]+)""",
    """\Wsuser=({user_fullname}\w+(\s+\w+)+)""",
  ]
}
```