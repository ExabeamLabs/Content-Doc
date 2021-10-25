#### Parser Content
```Java
{
Name = cef-github-app-activity
  Vendor = GitHub
  Product = GitHub
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """destinationServiceName=GitHub""" ]
  Fields = [
    """"created_at":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"display_login":"({user}[^"]{1,2000})"""",
    """"type":"({activity}[^"]{1,2000}?)(?:Event|)"""",
    """\WrequestClientApplication=({app}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """"repo":[^}]{1,2000}?"name":"({resource}[^"]{1,2000})"""",
    """"repo":[^}]{1,2000}?"name":"({object}[^"]{1,2000})"""",
    """\Wfname=({object}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\WfileType=({additional_info}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\Wmsg=({additional_info}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
  ]
}
```