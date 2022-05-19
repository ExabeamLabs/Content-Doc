#### Parser Content
```Java
{
Name = zoom-login
  Vendor = Zoom
  Product = Zoom
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"type":"Sign in"""", """destinationServiceName =Zoom""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\WdestinationServiceName =({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """"type":"({activity}[^"]{1,2000})"""",
    """"email":"({user_email}[^"]{1,2000})"""",
    """\Wmsg=({additional_info}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"ip_address":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
    """"client_type"\s{0,100}:\s{0,100}"({client_type}[^"]{1,2000})"""",
    """"version"\s{0,100}:\s{0,100}"({app_version}[^"]{1,2000})""""
  ]


}
```