#### Parser Content
```Java
{
Name = cef-trendmicro-security-alert-9
  Vendor = Trend Micro
  Product = Cloud App Security
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Trend Micro|CAS|""", """TrendMicroCasAffectedUser=""", """|securityrisk|""" ]
  Fields = [
    """\Wrt=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""",
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^\s]{1,2000})""",
    """\WdestinationServiceName=({app}.+?)\s\w+=""",
    """\Wcat=({alert_type}.+?)\s\w+=""",
    """\Wmsg=({additional_info}.+?)\s\w+=""",
    """\Wcs2=(|({additional_info}.+?))\s\w+=""",
    """\WTrendMicroCasAffectedUser=({user}.+?)\s\w+=""",
    """\WTrendMicroCasAffectedUser=({user_email}({user}[^@]{1,2000})@({domain}[^\.]{1,2000}).+?)\s\w+=""",
    """\WTrendMicroCasLocation=({malware_url}.+?)\s\w+=""",
    """\Woutcome=({outcome}.+?)\s\w+=""",
    """\Wfname=({file_name}.+?)\s\w+=""",
    """\Wcs2=(|({alert_name}.+?))\s\w+=""",
    """\Wcs1=(|({alert_name}.+?))\s\w+=""",
  ]
}
```