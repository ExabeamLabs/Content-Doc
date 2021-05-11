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
    """\WdestinationServiceName=({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wend=({time}\d{1,100})""",
    """\WflexString1=(|({activity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssuser=([^\s]+\/)?({user_email}[^\s@]+@[^\s@]+)\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """"client_type"\s{0,100}:\s{0,100}"({client_type}[^"]+)"""",
    """"version"\s{0,100}:\s{0,100}"({app_version}[^"]+)""""
  ]
}
```