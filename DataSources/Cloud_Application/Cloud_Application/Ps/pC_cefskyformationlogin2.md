#### Parser Content
```Java
{
Name = cef-skyformation-login-2
  Vendor = Cloud Application
  Product = Cloud Application
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """|Skyformation|""", """"Action":"Login"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\WdestinationServiceName=({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wend=({time}\d{1,100})""",
    """\Wdproc=({process_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wfname=(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmsg=({additional_info}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsuser=({user_email}[^@\s]{1,2000}@({email_domain}[^@\s]{1,2000}))""",
    """\Wsuser=({user_fullname}\w+(\s{1,100}\w+)+)""",
  ]
}
```