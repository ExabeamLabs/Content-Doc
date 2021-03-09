#### Parser Content
```Java
{
Name = zoom-login
  Vendor = Zoom
  Product = Zoom
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """|Skyformation|""", """|login-success|""", """destinationServiceName=Zoom""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\WdestinationServiceName=({app}.+?)(\s+\w+=|\s*$)""",
    """\Wend=({time}\d+)""",
    """\WflexString1=(|({activity}.+?))(\s+\w+=|\s*$)""",
    """\ssuser=([^\s]+\/)?({user_email}[^\s@]+@[^\s@]+)\s+(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """"client_type"\s*:\s*"({client_type}[^"]+)"""",
    """"version"\s*:\s*"({app_version}[^"]+)""""
  ]
}
```