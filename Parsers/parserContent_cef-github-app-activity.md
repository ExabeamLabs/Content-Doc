#### Parser Content
```Java
{
Name = cef-github-app-activity
  Vendor = GitHub
  Product = GitHub
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=GitHub""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) ({host}\S+) Skyformation -""",
    """\Wsuser=({user}[^\s]+)""",
    """\WflexString1=({activity}.+?)(?:Event|)\s*(\w+=|$)""",
    """\WrequestClientApplication=({app}.+?)\s*(\w+=|$)""",
    """\Wdproc=({resource}.+?)\s*(\w+=|$)""",
    """\Wdproc=({object}.+?)\s*(\w+=|$)""",
    """\Wfname=({object}.+?)\s*(\w+=|$)""",
    """\WfileType=({additional_info}.+?)\s*(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s*(\w+=|$)""",
  ]
}
```