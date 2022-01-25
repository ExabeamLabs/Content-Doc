#### Parser Content
```Java
{
Name = zoom-login
  Vendor = Zoom
  Product = Zoom
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """|Skyformation|""", """|login-success|""", """destinationServiceName =Zoom""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\WdestinationServiceName =({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wend=({time}\d{1,100})""",
    """\WflexString1=(|({activity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssuser=([^\s]{1,2000}\/)?({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"client_type"\s{0,100}:\s{0,100}"({client_type}[^"]{1,2000})"""",
    """"version"\s{0,100}:\s{0,100}"({app_version}[^"]{1,2000})""""
  ]


}
```