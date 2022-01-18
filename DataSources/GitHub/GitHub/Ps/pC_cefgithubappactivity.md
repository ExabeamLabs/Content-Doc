#### Parser Content
```Java
{
Name = cef-github-app-activity
  Vendor = GitHub
  Product = GitHub
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName =GitHub""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) \S+ Skyformation -""",
    """\Wsuser=({user}[^\s]{1,2000})""",
    """\WflexString1=({activity}.+?)(?:Event|)\s{0,100}(\w+=|$)""",
    """\WrequestClientApplication=({app}.+?)\s{0,100}(\w+=|$)""",
    """\Wdproc=({resource}.+?)\s{0,100}(\w+=|$)""",
    """\Wdproc=({object}.+?)\s{0,100}(\w+=|$)""",
    """\Wfname=({object}.+?)\s{0,100}(\w+=|$)""",
    """\WfileType=({additional_info}.+?)\s{0,100}(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s{0,100}(\w+=|$)""",
  ]


}
```